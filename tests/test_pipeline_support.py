import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from botocore.exceptions import ClientError

from app.pipeline_support import (
    acquire_run,
    require_fresh,
    run_identifier,
)


def conditional_failure():
    return ClientError(
        {
            "Error": {
                "Code": "ConditionalCheckFailedException",
                "Message": "Synthetic condition failure",
            }
        },
        "PutItem",
    )


def priorities_fixture():
    return {
        "policy": {"version": "exercise-1"},
        "candidates_sha256": "candidate-hash",
        "sources": {
            "kev": {"raw_sha256": "kev-hash"},
            "epss": {"raw_sha256": "epss-hash"},
        },
    }


class PipelineSupportTests(unittest.TestCase):
    def test_fresh_source_is_accepted(self):
        now = datetime.now(timezone.utc).isoformat()
        require_fresh(now, 7)

    def test_stale_source_is_rejected(self):
        old = (
            datetime.now(timezone.utc) - timedelta(days=10)
        ).isoformat()

        with self.assertRaisesRegex(ValueError, "freshness"):
            require_fresh(old, 7)

    def test_future_source_is_rejected(self):
        future = (
            datetime.now(timezone.utc) + timedelta(days=3)
        ).isoformat()

        with self.assertRaisesRegex(ValueError, "future"):
            require_fresh(future, 7)

    def test_new_run_can_be_claimed(self):
        table = Mock()

        result = acquire_run(table, "run-1", "owner-1", 1000)

        self.assertIsNone(result)
        request = table.put_item.call_args.kwargs
        self.assertEqual(request["Item"]["lease_until"], 1900)
        self.assertIn(
            "attribute_not_exists", request["ConditionExpression"]
        )

    def test_completed_run_is_skipped(self):
        table = Mock()
        table.put_item.side_effect = conditional_failure()
        table.get_item.return_value = {
            "Item": {
                "status": "COMPLETE",
                "report_key": "runs/example/report.md",
            }
        }

        result = acquire_run(table, "run-1", "owner-2", 1000)

        self.assertEqual(result["status"], "COMPLETE")
        table.get_item.assert_called_once_with(
            Key={"run_id": "run-1"}, ConsistentRead=True
        )

    def test_busy_run_is_not_reported_as_success(self):
        table = Mock()
        table.put_item.side_effect = conditional_failure()
        table.get_item.return_value = {
            "Item": {"status": "RUNNING"}
        }

        with self.assertRaisesRegex(RuntimeError, "in progress"):
            acquire_run(table, "run-1", "owner-2", 1000)

    def test_identical_inputs_have_same_run_id(self):
        first = run_identifier(
            priorities_fixture(), {"assets": []}, {"rules": []}
        )
        second = run_identifier(
            priorities_fixture(), {"assets": []}, {"rules": []}
        )
        self.assertEqual(first, second)

    def test_changed_inventory_changes_run_id(self):
        first = run_identifier(
            priorities_fixture(), {"assets": []}, {"rules": []}
        )
        second = run_identifier(
            priorities_fixture(),
            {"assets": [{"asset_id": "new"}]},
            {"rules": []},
        )
        self.assertNotEqual(first, second)

    def test_changed_source_changes_run_id(self):
        original = priorities_fixture()
        changed = priorities_fixture()
        changed["sources"]["epss"]["raw_sha256"] = "changed"

        self.assertNotEqual(
            run_identifier(original, {}, {}),
            run_identifier(changed, {}, {}),
        )


if __name__ == "__main__":
    unittest.main()