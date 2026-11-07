import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "adv001_detector",
    ROOT / "detections/adv001_detector.py",
)

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestADV001(unittest.TestCase):
    def setUp(self):
        self.event = {
            "Scenario": "ADV-001",
            "Technique": "T1059.001",
            "EventId": 4688,
            "ProcessName": (
                "C:\\Windows\\System32\\WindowsPowerShell\\"
                "v1.0\\powershell.exe"
            ),
            "ParentProcessName": (
                "C:\\Windows\\System32\\WindowsPowerShell\\"
                "v1.0\\powershell.exe"
            ),
            "CommandLine": (
                'powershell.exe -NoProfile -NonInteractive '
                '-Command "Write-Output '
                "'ADV-001-20261106-205332'; Get-Date\""
            ),
            "TestId": "ADV-001-20261106-205332",
        }

    def test_positive(self):
        self.assertTrue(module.detect(self.event))

    def test_wrong_event_id(self):
        event = self.event.copy()
        event["EventId"] = 4624
        self.assertFalse(module.detect(event))

    def test_wrong_process(self):
        event = self.event.copy()
        event["ProcessName"] = "C:\\Windows\\System32\\notepad.exe"
        self.assertFalse(module.detect(event))

    def test_missing_identifier(self):
        event = self.event.copy()
        event["TestId"] = "ADV-001-20261106-999999"
        self.assertFalse(module.detect(event))

    def test_missing_command_line(self):
        event = self.event.copy()
        event["CommandLine"] = ""
        self.assertFalse(module.detect(event))

    def test_malformed_identifier(self):
        event = self.event.copy()
        event["TestId"] = "INVALID"
        self.assertFalse(module.detect(event))


if __name__ == "__main__":
    unittest.main()
