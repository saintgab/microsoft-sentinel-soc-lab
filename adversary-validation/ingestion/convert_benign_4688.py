"""Convert a verified benign Windows 4688 XML event to the lab DCR schema."""

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def convert(path):
    root = ET.parse(path).getroot()

    event_id = root.findtext("./e:System/e:EventID", namespaces=NS)
    record_id = root.findtext(
        "./e:System/e:EventRecordID", namespaces=NS
    )
    time_element = root.find("./e:System/e:TimeCreated", NS)

    fields = {
        element.get("Name"): element.text or ""
        for element in root.findall("./e:EventData/e:Data", NS)
    }

    process = fields.get("NewProcessName", "")
    command = fields.get("CommandLine", "")

    if event_id != "4688" or record_id != "95761":
        raise ValueError("Unexpected Windows event identity")

    if time_element is None:
        raise ValueError("Missing event timestamp")

    if not process.lower().endswith("\\powershell.exe"):
        raise ValueError("Expected Windows PowerShell process")

    if (
        "get-date" not in command.lower()
        or "adv-001-" in command.lower()
    ):
        raise ValueError("Not the expected benign command")

    timestamp = datetime.fromisoformat(
        time_element.attrib["SystemTime"].replace("Z", "+00:00")
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
        "CorrelationId": "BENIGN-4688-95761",
        "RawData": json.dumps({
            "EvidenceOrigin": "Windows Security Event Log",
            "CollectionMethod": "ManualEvidenceExport",
            "OriginalEventId": 4688,
            "OriginalRecordId": 95761,
            "CommandLine": command,
            "ExpectedClassification": "Benign",
        }),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    record = convert(args.input)
    args.output.write_text(
        json.dumps([record], indent=2) + "\n",
        encoding="utf-8",
    )

    print("PASS: Benign 4688 event converted.")
    print("PASS: Existing 10-column schema preserved.")
    print("Correlation ID:", record["CorrelationId"])
    print("Azure ingestion: NOT PERFORMED")


if __name__ == "__main__":
    main()
