import json
import unittest
from datetime import datetime, timezone

from app.normalize import PROJECT_ROOT


def main():
    suite = unittest.defaultTestLoader.discover(
        str(PROJECT_ROOT / "tests"),
        pattern="test_*.py",
    )

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "passed": result.wasSuccessful() and result.testsRun > 0,
    }

    folder = PROJECT_ROOT / "reports"
    folder.mkdir(exist_ok=True)
    path = folder / "local-test-results.json"
    path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print(f"Summary saved to: {path}")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())