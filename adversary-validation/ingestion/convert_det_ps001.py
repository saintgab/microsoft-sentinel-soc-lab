"""Convert the verified DET-PS-001 Windows event to the lab DCR schema."""

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

CORRELATION_ID = "DET-PS-001-4688-96538"


def convert(path):
    root = ET.parse(path).getroot()

    event_id = root.findtext("./e:System/e:EventID", namespaces=NS)
    record_id = root.findtext(
        "./e:System/e:EventRecordID", namespaces=NS
    )
    timestamp_element = root.find("./e:System/e:TimeCreated", NS)

    fields = {
        item.get("Name"): item.text or ""
        for item in root.findall("./e:EventData/e:Data", NS)
    }

    process = fields.get("NewProcessName", "")
    command = fields.get("CommandLine", "")

    if event_id != "4688" or record_id != "96538":
        raise ValueError("Unexpected Windows event identity")

    if timestamp_element is None:
        raise ValueError("Missing original event timestamp")

    if not process.lower().endswith("\\powershell.exe"):
        raise ValueError("Unexpected process")

    if "-encodedcommand" not in command.lower():
        raise ValueError("EncodedCommand argument missing")

    timestamp = datetime.fromisoformat(
        timestamp_element.attrib["SystemTime"].replace("Z", "+00:00")
    ).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "TimeGenerated": timestamp,
        "EventType": "WindowsProcessCreation",
        "UserId": "",
        "SourceIP": "",
        "Destination": process,
        "Action": "ProcessCreated",
        "Result": "Observed",
        "RiskScore": 0,
        "CorrelationId": CORRELATION_ID,
        "RawData": json.dumps({
            "EvidenceOrigin": "Windows Security Event Log",
            "CollectionMethod": "ManualEvidenceExport",
            "OriginalEventId": 4688,
            "OriginalRecordId": 96538,
            "CommandLine": command,
            "SimulationType": "HarmlessEncodedPowerShell",
        }),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    record = convert(args.input)

    args.output.write_text(
        json.dumps([record], indent=2) + "\n",
        encoding="utf-8",
    )

    print("PASS: DET-PS-001 event converted.")
    print("PASS: Original event timestamp preserved.")
    print("PASS: Existing 10-column schema preserved.")
    print("Correlation ID:", record["CorrelationId"])
    print("Azure ingestion: NOT PERFORMED")


if __name__ == "__main__":
    main()
