from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

fixtures = {
    "tests/fixtures/SOC-LAB-003-test.kql": {
        "Positive", "MissingPrivilege",
        "WrongOrder", "TooSlow"
    },
    "tests/edge-cases/SOC-LAB-003-repeated-events.kql": {
        "ValidSequence", "RepeatedEvents", "MixedOrder"
    },
    "tests/edge-cases/SOC-LAB-003-session-aware.kql": {
        "ValidSequence", "MixedSessions"
    },
}

errors = []

for relative_path, scenarios in fixtures.items():
    path = ROOT / relative_path

    if not path.is_file():
        errors.append(f"{relative_path}: missing file")
        continue

    query = path.read_text(encoding="utf-8")

    checks = {
        "datatable source": query.lstrip().startswith("datatable("),
        "minimum query length": len(query.splitlines()) >= 25,
        "scenario coverage": all(
            f'"{scenario}"' in query for scenario in scenarios
        ),
        "chronological validation":
            "FailedLoginTime < LoginTime" in query
            and "FileAccessTime < TransferTime" in query,
        "30-minute window":
            "TransferTime - FailedLoginTime <= 30m" in query,
        "PASS/FAIL output":
            '"PASS", "FAIL"' in query,
        "no trailing blank lines":
            query.endswith("\n") and not query.endswith("\n\n"),
    }

    if "session-aware" in relative_path:
        checks["session grouping"] = "by Scenario, SessionId" in query
        checks["session counts"] = (
            "MatchingSessions = countif(SessionMatch)" in query
        )

    for name, passed in checks.items():
        print(f'{"PASS" if passed else "FAIL"}: {relative_path} - {name}')
        if not passed:
            errors.append(f"{relative_path}: {name}")

if errors:
    print(f"\nFIXTURE VALIDATION FAILED: {len(errors)} issues")
    sys.exit(1)

print("\nALL KQL FIXTURE STRUCTURE CHECKS PASSED")
print("KQL execution against Azure: NOT PERFORMED")
