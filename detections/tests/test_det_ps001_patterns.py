"""Local regex regression tests for DET-PS-001.

These tests evaluate the regex extracted from the actual KQL file.
Python re and Azure KQL's RE2 are different regex engines.
These tests do not replace Azure KQL execution or Windows parser testing.
"""

import re
import unittest
from pathlib import Path


KQL_PATH = (
    Path(__file__).resolve().parents[1]
    / "DET-PS-001-encoded-powershell.kql"
)


def load_detection_pattern():
    source = KQL_PATH.read_text(encoding="utf-8")

    matches = re.findall(
        r'matches regex @"([^"]+)"',
        source,
    )

    if len(matches) != 1:
        raise AssertionError(
            f"Expected exactly one detection regex, found {len(matches)}"
        )

    return re.compile(matches[0])


PATTERN = load_detection_pattern()


POSITIVE_CASES = {
    "full_parameter": "powershell.exe -EncodedCommand AAAA",
    "standard_alias": "powershell.exe -enc AAAA",
    "mixed_case": "powershell.exe -EnC AAAA",
    "short_alias_ec": "powershell.exe -ec AAAA",
    "short_alias_en": "powershell.exe -en AAAA",
    "prefix_enco": "powershell.exe -enco AAAA",
    "prefix_encodedcomm": "powershell.exe -EncodedComm AAAA",
    "single_letter": "powershell.exe -e AAAA",
    "with_noprofile": (
        "powershell.exe -NoProfile -EncodedCommand AAAA"
    ),
    "en_dash": "powershell.exe –EncodedCommand AAAA",
    "em_dash": "powershell.exe —enc AAAA",
    "horizontal_bar": "powershell.exe ―enc AAAA",
}

NEGATIVE_CASES = {
    "normal_command": "powershell.exe -Command Get-Date",
    "execution_policy": (
        "powershell.exe -ExecutionPolicy Bypass"
    ),
    "quoted_e": 'powershell.exe -Command "echo -e x"',
    "quoted_enc": (
        'powershell.exe -Command "Write-Output \'-enc AAAA\'"'
    ),
    "noprofile": "powershell.exe -NoProfile",
    # This cmd.exe event is excluded by Destination. A separately
    # logged child powershell.exe event could still match DET-PS-001.
    "different_process": "cmd.exe /c powershell.exe -EncodedCommand AAAA",
}


def detector_matches(command, destination):
    """Evaluate executable filtering and the detection regex together."""
    return (
        destination.lower().endswith("\\powershell.exe")
        and PATTERN.search(command) is not None
    )


POWERSHELL_PATH = (
    "C:\\Windows\\System32\\WindowsPowerShell\\"
    "v1.0\\powershell.exe"
)

CMD_PATH = "C:\\Windows\\System32\\cmd.exe"


class TestDetPs001Patterns(unittest.TestCase):

    def test_positive_variants(self):
        for name, command in POSITIVE_CASES.items():
            with self.subTest(case=name):
                self.assertTrue(
                    detector_matches(command, POWERSHELL_PATH),
                    f"Missed expected variant: {name}",
                )

    def test_negative_variants(self):
        for name, command in NEGATIVE_CASES.items():
            with self.subTest(case=name):
                destination = (
                    CMD_PATH if name == "different_process"
                    else POWERSHELL_PATH
                )
                self.assertFalse(
                    detector_matches(command, destination),
                    f"Unexpected match: {name}",
                )


if __name__ == "__main__":
    unittest.main()
