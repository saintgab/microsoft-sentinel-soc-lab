"""Convert a genuine ADV-001 Windows event export into a DCR record."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def convert(event):
    if event.get("EventId") != 4688:
        raise ValueError("Expected Windows Event ID 4688")

    test_id = event.get("TestId", "")
    command = event.get("CommandLine", "")
    process = event.get("ProcessName", "")

    if (
        not test_id.startswith("ADV-001-")
        or test_id not in command
        or not process.lower().endswith("\\powershell.exe")
    ):
        raise ValueError("Event does not match ADV-001 evidence")

    timestamp = datetime.fromisoformat(
        event["TimeCreated"].replace("Z", "+00:00")
    ).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    raw_data = {
        "EvidenceOrigin": "Windows Security Event Log",
        "CollectionMethod": "ManualEvidenceExport",
        "OriginalEvent": event,
    }

    return {
        "TimeGenerated": timestamp,
        "EventType": "WindowsProcessCreation",
        "UserId": "",
        "SourceIP": "",
        "Destination": process,
        "Action": "ProcessCreated",
        "Result": "Observed",
        "RiskScore": 0,
        "CorrelationId": test_id,
        "RawData": json.dumps(raw_data, separators=(",", ":")),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    event = json.loads(args.input.read_text(encoding="utf-8-sig"))
    record = convert(event)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps([record], indent=2) + "\n",
        encoding="utf-8",
    )

    print("PASS: ADV-001 converted to DCR-compatible JSON")
    print("Output:", args.output)
    print("Test ID:", record["CorrelationId"])
    print("Records: 1")
    print("Azure ingestion: NOT PERFORMED")


if __name__ == "__main__":
    main()
