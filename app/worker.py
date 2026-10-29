import hashlib
import json
import os
import time
from datetime import datetime, timezone

import boto3

from app.analyze import CLIENT_CONFIG, analyze
from app.render_report import render_report


def lambda_handler(event, context):
    started = time.perf_counter()
    bucket = os.environ["DATA_BUCKET"]
    input_key = "inputs/prioritized.json"

    try:
        s3 = boto3.client("s3")
        source = s3.get_object(Bucket=bucket, Key=input_key)

        stream = source["Body"]
        try:
            raw = stream.read(5 * 1024 * 1024 + 1)
        finally:
            stream.close()

        if len(raw) > 5 * 1024 * 1024:
            raise ValueError("Input exceeds worker size limit.")

        priorities = json.loads(raw.decode("utf-8-sig"))

        model = boto3.client(
            "bedrock-runtime",
            region_name="us-east-1",
            config=CLIENT_CONFIG,
        )
        analysis = analyze(priorities, model)
        report = render_report(priorities, analysis)

        analysis_bytes = json.dumps(
            analysis, indent=2, allow_nan=False
        ).encode("utf-8")
        report_bytes = report.encode("utf-8")

        prefix = f"runs/{context.aws_request_id}"

        for name, data, content_type in (
            ("analysis.json", analysis_bytes, "application/json"),
            ("report.md", report_bytes, "text/markdown; charset=utf-8"),
        ):
            s3.put_object(
                Bucket=bucket,
                Key=f"{prefix}/{name}",
                Body=data,
                ContentType=content_type,
                ServerSideEncryption="AES256",
            )

        completion = {
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "input_key": input_key,
            "input_version_id": source.get("VersionId"),
            "input_sha256": hashlib.sha256(raw).hexdigest(),
            "candidate_count": len(analysis["analyses"]),
            "analysis_sha256": hashlib.sha256(
                analysis_bytes
            ).hexdigest(),
            "report_sha256": hashlib.sha256(
                report_bytes
            ).hexdigest(),
        }

        # Consumers should only use runs with this marker.
        s3.put_object(
            Bucket=bucket,
            Key=f"{prefix}/complete.json",
            Body=json.dumps(completion).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )

        print(json.dumps({
            "event": "run_completed",
            "request_id": context.aws_request_id,
            "candidate_count": completion["candidate_count"],
            "duration_ms": round(
                (time.perf_counter() - started) * 1000, 2
            ),
        }))

        return {
            "status": "complete",
            "bucket": bucket,
            "report_key": f"{prefix}/report.md",
            "completion_key": f"{prefix}/complete.json",
        }

    except Exception as error:
        print(json.dumps({
            "event": "run_failed",
            "request_id": context.aws_request_id,
            "error_type": type(error).__name__,
        }))

        # Preserve a failed Lambda invocation for monitoring.
        raise RuntimeError("Threat intelligence worker failed.") from None