# DET-PS-001 — Encoded PowerShell Detection

## Objective

Detect Windows PowerShell process creation involving the
EncodedCommand execution argument.

MITRE ATT&CK: T1059.001 — PowerShell.

## Detection source

- Platform: Microsoft Sentinel / Azure Log Analytics
- Table: SOCSecurityEvents_CL
- Original telemetry: Windows Security Event ID 4688
- Collection: Manual event export and Azure Logs Ingestion API
- Detection file: detections/DET-PS-001-encoded-powershell.kql

## Positive validation

- Correlation ID: DET-PS-001-4688-96538
- Original Windows Event Record ID: 96538
- Original timestamp: 2026-11-09T00:35:51.238771Z
- Process: powershell.exe
- Behavior: -EncodedCommand
- Payload: Harmless Write-Output command
- Event observed in Azure: 1
- Detection matches: 1
- Result: PASS

## Negative validation

- Correlation ID: BENIGN-4688-95761
- Original Windows Event Record ID: 95761
- Behavior: powershell.exe -NoProfile -Command Get-Date
- Event observed in Azure: 1
- Detection matches: 0
- Result: PASS

## Automated validation

- Python ingestion and payload validation tests: 21 passed
- Azure historical regression: 2 cases passed
- Regression KQL: detections/tests/DET-PS-001-regression.kql

## Expanded detection coverage

The DET-PS-001 matching expression was extended to recognize additional
encoded-command abbreviations and selected Unicode dash variants.

### Validation results

| Validation | Cases | Result |
| --- | ---: | --- |
| Python detection-pattern examples | 18 | PASS |
| Azure synthetic command-line examples | 18 | PASS |
| Azure full detection predicate scenarios | 6 | PASS |
| Genuine Windows Event 4688 regression | 2 | PASS |
| Python ingestion and payload validation | 21 | PASS |

The 18 Python examples are grouped into two unittest methods, using
subtests for the individual cases.

The six Azure predicate scenarios test event type, process action,
executable filtering, command-line matching, and negative controls.

The two genuine Windows events establish that the revised detection
continues to recognize the harmless encoded-command execution while
excluding the benign Get-Date execution.

### Coverage boundaries

- Synthetic command-line matches do not establish that Windows PowerShell
  accepts every abbreviation or Unicode dash variant.
- Python regex checks do not replace Azure KQL execution.
- The Python detection tests exercise executable filtering and the regex;
  they do not reproduce every KQL predicate.
- Quoted-command handling is heuristic, not a complete PowerShell parser.
- Encoded-command execution is an investigative signal, not proof of
  malicious behavior.
- The additional synthetic cases were executed manually in Azure;
  they are not yet part of the scheduled GitHub Actions regression.

## Interpretation

The detection matched the encoded-command execution argument
without relying on the test event's correlation ID.

The positive sample was a harmless, controlled execution and
does not establish malicious intent.

## Limitations

- Only two controlled Windows events were used in the Azure regression.
- Production false-positive and false-negative rates are unknown.
- Current rule targets powershell.exe, not PowerShell 7 pwsh.exe.
- Only selected encoded-command argument forms are included.
- The custom table uses manually ingested event evidence;
  continuous production collection has not been established.
- The rule has not been demonstrated as an enabled Sentinel
  analytics rule generating incidents.
- Raw Windows evidence files are intentionally excluded from GitHub.
- Historical regression uses fixed November 2026 event timestamps.
  It will fail if those records expire under the configured retention
  policy for SOCSecurityEvents_CL. Verify the table retention setting
  before assigning an expiry date; do not assume a 30- or 90-day period.

## Next engineering opportunities

- Expand command-line variants and negative test coverage.
- Add PowerShell 7 detection where telemetry is available.
- Evaluate legitimate administrative use and false positives.
- Validate production-style telemetry collection and alert lifecycle.
