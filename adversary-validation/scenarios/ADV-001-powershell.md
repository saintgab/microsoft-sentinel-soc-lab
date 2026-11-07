# ADV-001 — PowerShell Execution Telemetry Validation

## Objective
Validate detection visibility for PowerShell execution on an
authorized Windows lab endpoint.

## MITRE ATT&CK
Technique: T1059.001 — PowerShell
Tactic: Execution

## Hypothesis
PowerShell execution should generate process-related telemetry
that can be collected, investigated, and correlated by a
security monitoring platform.

## Planned simulation
Execute a benign PowerShell command on an isolated Windows
test system.

No credential access, persistence, evasion, or destructive
behavior is permitted.

## Required telemetry
- Timestamp
- Hostname or device identifier
- Executable name
- Process command line
- Parent process information
- User identity

## Expected data sources
- Windows Security Event ID 4688, when configured
- Microsoft Defender for Endpoint DeviceProcessEvents,
  when licensed and onboarded
- Sysmon Event ID 1, when installed and configured

## Success criteria
1. Benign command executes successfully.
2. Endpoint telemetry records the execution.
3. Security query identifies the test event.
4. Evidence is captured.
5. Detection gaps are documented.

## Safety
Only execute on an authorized Windows test endpoint.
Do not disable endpoint protection or clear event logs.

## Current status
PLANNED — no execution or telemetry validation performed.
