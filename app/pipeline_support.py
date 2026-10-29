from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from app.analyze import MODEL_ID, SYSTEM_PROMPT
from app.normalize import fingerprint


PIPELINE_VERSION = "scheduled-1"


def require_fresh(timestamp, max_age_days):
    if not isinstance(timestamp, str):
        raise ValueError("Source timestamp must be text.")

    moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    if moment > now + timedelta(days=1):
        raise ValueError("Source timestamp is unexpectedly in the future.")

    if now - moment > timedelta(days=max_age_days):
        raise ValueError("Source data exceeds the freshness limit.")


def run_identifier(priorities, inventory, rules):
    return fingerprint({
        "pipeline_version": PIPELINE_VERSION,
        "model_id": MODEL_ID,
        "system_prompt": SYSTEM_PROMPT,
        "policy": priorities["policy"],
        "candidate_hash": priorities["candidates_sha256"],
        "source_hashes": {
            name: source["raw_sha256"]
            for name, source in priorities["sources"].items()
        },
        "inventory_hash": fingerprint(inventory),
        "rules_hash": fingerprint(rules),
    })


def acquire_run(table, run_id, owner, now):
    try:
        table.put_item(
            Item={
                "run_id": run_id,
                "status": "RUNNING",
                "owner": owner,
                "lease_until": now + 900,
            },
            ConditionExpression=(
                "attribute_not_exists(run_id) OR "
                "(#status <> :complete AND lease_until < :now)"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":complete": "COMPLETE",
                ":now": now,
            },
        )
        return None

    except ClientError as error:
        if error.response["Error"]["Code"] != (
            "ConditionalCheckFailedException"
        ):
            raise

        item = table.get_item(
            Key={"run_id": run_id},
            ConsistentRead=True,
        ).get("Item", {})

        if item.get("status") == "COMPLETE":
            return item

        raise RuntimeError("An equivalent run is already in progress.") from None


def finish_run(table, run_id, owner, report_key):
    table.update_item(
        Key={"run_id": run_id},
        UpdateExpression=(
            "SET #status = :complete, report_key = :report, "
            "lease_until = :zero"
        ),
        ConditionExpression="#owner = :owner AND #status = :running",
        ExpressionAttributeNames={
            "#status": "status",
            "#owner": "owner",
        },
        ExpressionAttributeValues={
            ":complete": "COMPLETE",
            ":running": "RUNNING",
            ":report": report_key,
            ":zero": 0,
            ":owner": owner,
        },
    )


def fail_run(table, run_id, owner):
    table.update_item(
        Key={"run_id": run_id},
        UpdateExpression="SET #status = :failed, lease_until = :zero",
        ConditionExpression="#owner = :owner AND #status = :running",
        ExpressionAttributeNames={
            "#status": "status",
            "#owner": "owner",
        },
        ExpressionAttributeValues={
            ":failed": "FAILED",
            ":running": "RUNNING",
            ":zero": 0,
            ":owner": owner,
        },
    )