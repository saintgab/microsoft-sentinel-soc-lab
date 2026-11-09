"""Regression tests for the ADV-001 benign-event sender exception."""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SENDER = ROOT / "ingestion" / "send_adv001_event.py"

spec = importlib.util.spec_from_file_location("adv001_sender", SENDER)
sender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sender)


def benign_record():
    return {
        "TimeGenerated": "2026-11-08T22:29:52.019602Z",
        "EventType": "WindowsProcessCreation",
        "UserId": "",
        "SourceIP": "",
        "Destination": (
            "C:\\Windows\\System32\\WindowsPowerShell\\"
            "v1.0\\powershell.exe"
        ),
        "Action": "ProcessCreated",
        "Result": "Observed",
        "RiskScore": 0,
        "CorrelationId": "BENIGN-4688-95761",
        "RawData": json.dumps({
            "EvidenceOrigin": "Windows Security Event Log",
            "CollectionMethod": "ManualEvidenceExport",
            "OriginalEventId": 4688,
            "OriginalRecordId": 95761,
            "CommandLine": 'powershell.exe -NoProfile -Command Get-Date',
            "ExpectedClassification": "Benign",
        }),
    }


class TestBenignPayload(unittest.TestCase):

    def test_genuine_benign_record_accepted(self):
        self.assertEqual(
            sender.validate_payload([benign_record()])["CorrelationId"],
            "BENIGN-4688-95761",
        )

    def test_unknown_correlation_rejected(self):
        record = benign_record()
        record["CorrelationId"] = "UNKNOWN-4688-95761"

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_wrong_event_id_rejected(self):
        record = benign_record()
        raw = json.loads(record["RawData"])
        raw["OriginalEventId"] = 4624
        record["RawData"] = json.dumps(raw)

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_marker_in_benign_command_rejected(self):
        record = benign_record()
        raw = json.loads(record["RawData"])
        raw["CommandLine"] += " ADV-001-20261106-205332"
        record["RawData"] = json.dumps(raw)

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_unexpected_schema_rejected(self):
        record = benign_record()
        record["UnexpectedField"] = "value"

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])


if __name__ == "__main__":
    unittest.main()
