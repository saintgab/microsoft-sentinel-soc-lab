"""ADV-001: Validate a controlled PowerShell execution event."""

import re

TEST_ID_PATTERN = re.compile(r"ADV-001-\d{8}-\d{6}")


def detect(event):
    if event.get("EventId") != 4688:
        return False

    process = str(event.get("ProcessName") or "").lower()
    command = str(event.get("CommandLine") or "")

    if not process.endswith("\\powershell.exe"):
        return False

    test_id = event.get("TestId")

    if not isinstance(test_id, str):
        return False

    if TEST_ID_PATTERN.fullmatch(test_id) is None:
        return False

    return test_id in command
