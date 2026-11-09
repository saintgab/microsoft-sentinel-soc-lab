"""Regression tests for DET-PS-001 ingestion validation."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SENDER = ROOT / "ingestion" / "send_adv001_event.py"

spec = importlib.util.spec_from_file_location("det_ps001_sender", SENDER)
sender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sender)


def valid_record():
    return {
        "TimeGenerated": "2026-11-09T00:35:51Z",
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
        "CorrelationId": "DET-PS-001-4688-96538",
        "RawData": json.dumps({
            "EvidenceOrigin": "Windows Security Event Log",
            "CollectionMethod": "ManualEvidenceExport",
            "OriginalEventId": 4688,
            "OriginalRecordId": 96538,
            "CommandLine": (
                "powershell.exe -NoProfile "
                "-EncodedCommand VwByAGkAdABlAA=="
            ),
            "SimulationType": "HarmlessEncodedPowerShell",
        }),
    }


class TestDetPs001Payload(unittest.TestCase):

    def test_valid_encoded_powershell_accepted(self):
        record = sender.validate_payload([valid_record()])
        self.assertEqual(
            record["CorrelationId"],
            "DET-PS-001-4688-96538",
        )

    def test_wrong_event_id_rejected(self):
        record = valid_record()
        raw = json.loads(record["RawData"])
        raw["OriginalEventId"] = 4624
        record["RawData"] = json.dumps(raw)

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_wrong_record_id_rejected(self):
        record = valid_record()
        raw = json.loads(record["RawData"])
        raw["OriginalRecordId"] = 99999
        record["RawData"] = json.dumps(raw)

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_missing_encoded_command_rejected(self):
        record = valid_record()
        raw = json.loads(record["RawData"])
        raw["CommandLine"] = "powershell.exe -NoProfile -Command Get-Date"
        record["RawData"] = json.dumps(raw)

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_wrong_executable_rejected(self):
        record = valid_record()
        record["Destination"] = "C:\\Windows\\System32\\cmd.exe"

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_wrong_simulation_type_rejected(self):
        record = valid_record()
        raw = json.loads(record["RawData"])
        raw["SimulationType"] = "Unknown"
        record["RawData"] = json.dumps(raw)

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_unknown_correlation_rejected(self):
        record = valid_record()
        record["CorrelationId"] = "DET-PS-001-UNKNOWN"

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_unexpected_schema_rejected(self):
        record = valid_record()
        record["UnexpectedField"] = "value"

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_invalid_json_rejected(self):
        record = valid_record()
        record["RawData"] = "{invalid"

        with self.assertRaises(SystemExit):
            sender.validate_payload([record])

    def test_multiple_records_rejected(self):
        record = valid_record()

        with self.assertRaises(SystemExit):
            sender.validate_payload([record, copy.deepcopy(record)])


if __name__ == "__main__":
    unittest.main()
