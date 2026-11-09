# ADV-001 — PowerShell Execution Telemetry Validation Report

## Executive Summary

ADV-001 validates the visibility of controlled PowerShell execution
on an authorized Windows 11 endpoint.

A genuine Windows Security Event ID 4688 was exported, transformed
into the existing SOC lab ingestion schema, submitted through the
Azure Monitor Logs Ingestion API, and successfully queried in
Microsoft Sentinel's Log Analytics workspace.

The validation demonstrated end-to-end telemetry visibility and
successful positive/negative KQL matching.

## MITRE ATT&CK Mapping

- Technique: T1059.001 — PowerShell
- Tactic: Execution
- Simulation type: Benign PowerShell process execution

This exercise validates visibility into PowerShell execution.
It does not demonstrate malicious PowerShell behavior.

## Environment

- Endpoint: Windows 11 lab computer
- Original telemetry: Windows Security Event ID 4688
- Azure resource group: rg-sentinel-soc-lab
- Workspace: law-sentinel-soc-lab
- Destination table: SOCSecurityEvents_CL
- Ingestion: Azure Monitor Logs Ingestion API
- Authentication: Microsoft Entra service principal
- Validation: KQL and Python unittest
- CI: GitHub Actions

## Execution Summary

1. Enabled Windows process creation auditing and command-line capture.
2. Attempted to execute the saved PowerShell simulation script.
3. Windows PowerShell execution policy blocked the script file.
4. Successfully executed the benign simulation interactively.
5. Verified Windows Security Event ID 4688.
6. Exported the genuine event into JSON.
7. Mapped the event into the existing ten-column DCR schema.
8. Submitted one record through the Logs Ingestion API.
9. Received HTTP 204 from Azure Monitor.
10. Retrieved the matching record using Log Analytics KQL.
11. Executed positive and negative KQL validation tests.

## Evidence

Test identifier:

`ADV-001-20261106-205332`

Original event time:

`2026-11-07T02:53:32.4627678Z`

Azure ingestion result:

`HTTP 204`

KQL validation results:

| Test | Matches | Result |
|------|---------|--------|
| Positive | 1 | PASS |
| Negative | 0 | PASS |

Screenshots:

- [Sentinel ingestion evidence](../evidence/screenshots/ADV-001-sentinel-ingestion.png)
- [KQL validation evidence](../evidence/screenshots/ADV-001-kql-validation.png)

## Automated Validation

Six Python detector unit tests passed locally.

GitHub Actions Adversary Validation CI completed successfully.

## Detection Limitations

- Detection relies on a unique ADV-001 lab test identifier.
- It is not a general malicious PowerShell detection.
- Events were exported and forwarded manually.
- Continuous Windows endpoint monitoring was not configured.
- No Sentinel analytics-rule incident was generated.
- HTTP 204 indicates ingestion request acceptance;
  successful KQL retrieval separately confirmed record visibility.
- The positive and negative KQL tests used a known historical event.
- The Windows execution-policy restriction was preserved.

## Security Considerations

- No malicious payloads were executed.
- Windows endpoint protection was not disabled.
- The original endpoint evidence and ingestion payload are excluded
  from Git version control.
- Client secrets were supplied through a hidden prompt.
- Only the controlled test record was submitted to Azure.

## Conclusion

ADV-001 successfully demonstrated manual end-to-end collection,
ingestion, and investigation of genuine Windows process-creation
telemetry through Microsoft Sentinel.

Future enhancements should evaluate automated endpoint collection,
more behavior-oriented PowerShell detections, and scheduled
analytics-rule validation.

## Additional Genuine Benign-Event Validation — November 8, 2026

A second genuine Windows Security Event ID 4688 was collected from
the Windows 11 lab endpoint.

- Process: Windows PowerShell (`powershell.exe`)
- Command: `-NoProfile -Command Get-Date`
- Original event timestamp: `2026-11-08T22:29:52.0196024Z`
- Windows Event Record ID: `95761`
- Lab ingestion correlation ID: `BENIGN-4688-95761`
- Collection method: manual XML export and Azure Logs Ingestion API
- Source verification: original Windows XML inspected locally
- Result verification: matching event retrieved from `SOCSecurityEvents_CL`

### Azure KQL Results

| Measurement | Verified result |
|---|---:|
| Positive event observed | 1 |
| Positive event matched lab detector | 1 |
| Benign event observed | 1 |
| Benign event matched lab detector | 0 |
| Positive test | PASS |
| Negative test | PASS |

The negative test requires the benign event to be present in the
queried telemetry. A missing benign event causes the test to fail.

The detection condition is specific to the controlled ADV-001 lab
correlation marker. This exercise does not demonstrate reliable
malicious PowerShell classification or establish a false-positive rate.

The earlier negative test using `ADV-001-DOES-NOT-EXIST` has been
superseded by the validation above. Original Windows XML and ingestion
payloads remain private and are not committed to the repository.
