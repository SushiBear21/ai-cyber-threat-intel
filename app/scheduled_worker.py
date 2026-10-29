import hashlib
import json
import os
import time
import urllib.parse
from datetime import datetime, timezone

import boto3

from app.analyze import CLIENT_CONFIG, analyze
from app.assess_assets import (
    assess_findings,
    validate_inventory,
    validate_rules,
)
from app.collect_epss import ENDPOINT, validate_response
from app.collect_kev import SOURCE_URL, validate_catalog
from app.http_client import download_json_bytes
from app.normalize import fingerprint, normalize_findings
from app.pipeline_support import (
    acquire_run,
    fail_run,
    finish_run,
    require_fresh,
    run_identifier,
)
from app.prioritize import prioritize
from app.render_report import render_report


def read_config(s3, bucket, key):
    result = s3.get_object(Bucket=bucket, Key=key)
    stream = result["Body"]

    try:
        raw = stream.read(1024 * 1024 + 1)
    finally:
        stream.close()

    if len(raw) > 1024 * 1024:
        raise ValueError("Configuration exceeds size limit.")

    return json.loads(raw.decode("utf-8-sig"))


def fetch_source(url, limit):
    raw, final_url = download_json_bytes(url, limit)
    payload = json.loads(raw.decode("utf-8-sig"))

    provenance = {
        "requested_url": url,
        "retrieved_url": final_url,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return raw, payload, provenance


def put_bytes(s3, bucket, key, data, content_type):
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ContentType=content_type,
        ServerSideEncryption="AES256",
    )


def put_json(s3, bucket, key, value):
    raw = json.dumps(
        value, indent=2, allow_nan=False
    ).encode("utf-8")
    put_bytes(s3, bucket, key, raw, "application/json")
    return raw


def lambda_handler(event, context):
    started = time.perf_counter()
    stage = "configuration"
    table = None
    run_id = None
    claimed = False

    try:
        bucket = os.environ["DATA_BUCKET"]
        s3 = boto3.client("s3")
        table = boto3.resource("dynamodb").Table(
            os.environ["RUN_TABLE"]
        )

        inventory = read_config(s3, bucket, "inputs/assets.json")
        rules = read_config(s3, bucket, "inputs/review-rules.json")

        validate_inventory(inventory)
        validate_rules(rules)

        cves = sorted({rule["cve_id"] for rule in rules["rules"]})
        if not 1 <= len(cves) <= 10:
            raise ValueError("This pipeline requires 1–10 unique rule CVEs.")

        stage = "collection"

        kev_raw, kev, kev_source = fetch_source(
            SOURCE_URL, 20 * 1024 * 1024
        )
        validate_catalog(kev)
        require_fresh(kev["dateReleased"], 30)

        epss_url = ENDPOINT + "?" + urllib.parse.urlencode({
            "cve": ",".join(cves),
            "limit": len(cves),
        })
        epss_raw, epss, epss_source = fetch_source(
            epss_url, 2 * 1024 * 1024
        )
        missing = validate_response(epss, cves)

        for record in epss["data"]:
            require_fresh(record["date"], 7)

        kev_source["source"] = "CISA KEV official GitHub mirror"
        epss_source["source"] = "FIRST EPSS API"

        stage = "processing"

        findings = normalize_findings(kev, epss, cves)
        normalized = {
            "findings": findings,
            "findings_sha256": fingerprint(findings),
            "sources": {
                "kev": kev_source,
                "epss": epss_source,
            },
        }

        assessments = {
            "synthetic": True,
            "input_findings_sha256": normalized["findings_sha256"],
            "inventory_sha256": fingerprint(inventory),
            "review_rules_sha256": fingerprint(rules),
            **assess_findings(findings, inventory, rules),
        }

        priorities = prioritize(normalized, assessments)

        if len(priorities["candidates"]) > 3:
            raise ValueError("Scheduled sandbox run permits at most 3 candidates.")

        run_id = run_identifier(priorities, inventory, rules)

        stage = "claim"

        existing = acquire_run(
            table,
            run_id,
            context.aws_request_id,
            int(time.time()),
        )

        if existing is not None:
            print(json.dumps({
                "event": "run_skipped",
                "request_id": context.aws_request_id,
                "run_id": run_id,
                "reason": "already_complete",
            }))
            return {
                "status": "skipped",
                "run_id": run_id,
                "report_key": existing.get("report_key"),
            }

        claimed = True
        prefix = f"runs/{run_id}/{context.aws_request_id}"

        stage = "archive"

        put_bytes(
            s3, bucket, f"{prefix}/kev.json",
            kev_raw, "application/json",
        )
        put_bytes(
            s3, bucket, f"{prefix}/epss.json",
            epss_raw, "application/json",
        )
        put_json(s3, bucket, f"{prefix}/assets.json", inventory)
        put_json(s3, bucket, f"{prefix}/review-rules.json", rules)
        put_json(s3, bucket, f"{prefix}/prioritized.json", priorities)

        stage = "analysis"

        model = boto3.client(
            "bedrock-runtime",
            region_name="us-east-1",
            config=CLIENT_CONFIG,
        )
        analysis = analyze(priorities, model)

        stage = "report"

        report = render_report(priorities, analysis)
        analysis_raw = put_json(
            s3, bucket, f"{prefix}/analysis.json", analysis
        )
        report_raw = report.encode("utf-8")
        report_key = f"{prefix}/report.md"

        put_bytes(
            s3, bucket, report_key, report_raw,
            "text/markdown; charset=utf-8",
        )

        completion = {
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "request_id": context.aws_request_id,
            "candidate_count": len(priorities["candidates"]),
            "missing_epss_cves": missing,
            "sources": normalized["sources"],
            "report_key": report_key,
            "analysis_sha256": hashlib.sha256(
                analysis_raw
            ).hexdigest(),
            "report_sha256": hashlib.sha256(report_raw).hexdigest(),
            "review_status": "draft_pending_analyst_review",
        }

        completion_key = f"{prefix}/complete.json"
        put_json(s3, bucket, completion_key, completion)

        stage = "record_completion"

        finish_run(
            table, run_id, context.aws_request_id, report_key
        )

        print(json.dumps({
            "event": "run_completed",
            "request_id": context.aws_request_id,
            "run_id": run_id,
            "candidate_count": len(priorities["candidates"]),
            "duration_ms": round(
                (time.perf_counter() - started) * 1000, 2
            ),
        }))

        return {
            "status": "complete",
            "bucket": bucket,
            "run_id": run_id,
            "report_key": report_key,
            "completion_key": completion_key,
        }

    except Exception as error:
        if claimed:
            try:
                fail_run(table, run_id, context.aws_request_id)
            except Exception:
                # An unfinished lease expires after 15 minutes.
                pass

        record = {
            "event": "run_failed",
            "request_id": context.aws_request_id,
            "stage": stage,
            "error_type": type(error).__name__,
        }

        response = getattr(error, "response", None)
        if isinstance(response, dict):
            record["aws_error_code"] = response.get(
                "Error", {}
            ).get("Code")

        print(json.dumps(record))
        raise RuntimeError("Scheduled intelligence pipeline failed.") from None