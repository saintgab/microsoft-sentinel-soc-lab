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

- Python unit tests: 21 passed
- Azure historical regression: 2 cases passed
- Regression KQL: detections/tests/DET-PS-001-regression.kql

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
- Historical regression depends on the specified events remaining
  available within Azure Log Analytics retention.

## Next engineering opportunities

- Expand command-line variants and negative test coverage.
- Add PowerShell 7 detection where telemetry is available.
- Evaluate legitimate administrative use and false positives.
- Validate production-style telemetry collection and alert lifecycle.
