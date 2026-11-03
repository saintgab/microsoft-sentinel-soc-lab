import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FIXTURES = {
    "tests/fixtures/SOC-LAB-003-test.kql": 4,
    "tests/edge-cases/SOC-LAB-003-repeated-events.kql": 3,
    "tests/edge-cases/SOC-LAB-003-session-aware.kql": 2,
}


def main():
    workspace = os.environ.get("AZURE_LOG_ANALYTICS_WORKSPACE_ID")

    if not workspace:
        print("ERROR: AZURE_LOG_ANALYTICS_WORKSPACE_ID is required")
        return 1

    total = 0
    failed = 0

    for filename, expected_count in FIXTURES.items():
        print(f"\nTesting {filename}", flush=True)

        query = (ROOT / filename).read_text(encoding="utf-8")

        result = subprocess.run(
            [
                "az", "monitor", "log-analytics", "query",
                "--workspace", workspace,
                "--analytics-query", query,
                "--output", "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        rows = json.loads(result.stdout)

        if not isinstance(rows, list) or len(rows) != expected_count:
            raise RuntimeError(
                f"{filename}: expected {expected_count} rows"
            )

        expected_scenarios = {
            "tests/fixtures/SOC-LAB-003-test.kql": {
                "Positive", "MissingPrivilege", "WrongOrder", "TooSlow"
            },
            "tests/edge-cases/SOC-LAB-003-repeated-events.kql": {
                "ValidSequence", "RepeatedEvents", "MixedOrder"
            },
            "tests/edge-cases/SOC-LAB-003-session-aware.kql": {
                "ValidSequence", "MixedSessions"
            },
        }[filename]

        actual_scenarios = [row["Scenario"] for row in rows]

        if set(actual_scenarios) != expected_scenarios:
            raise RuntimeError(
                f"{filename}: unexpected scenario coverage"
            )

        if len(actual_scenarios) != len(set(actual_scenarios)):
            raise RuntimeError(
                f"{filename}: duplicate scenario results"
            )

        for row in rows:
            total += 1
            status = row["TestResult"]
            scenario = row["Scenario"]

            print(f"{status}: {scenario}", flush=True)

            if status != "PASS":
                failed += 1

    print(f"\nTOTAL: {total}")
    print(f"FAILED: {failed}")

    if failed or total != 9:
        return 1

    print("ALL 9 AZURE KQL REGRESSION TESTS PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
