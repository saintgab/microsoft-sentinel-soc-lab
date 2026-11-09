# SOC Lab Screenshot Evidence

These are authentic screenshots supplied during the lab session, copied without altering the underlying results.

## Threat hunting execution

### HUNT-001 — Authentication
![HUNT-001 Azure Log Analytics results](screenshots/threat-hunting/HUNT-001-authentication.png)

### HUNT-002 — Sensitive file access followed by transfer
![HUNT-002 Azure Log Analytics results](screenshots/threat-hunting/HUNT-002-data-transfer.png)

### HUNT-003 — Privilege changes
![HUNT-003 Azure Log Analytics results](screenshots/threat-hunting/HUNT-003-privilege-changes.png)

## Detection validation
![SOC-LAB-003 session-aware synthetic regression test](screenshots/detection-validation/SOC-LAB-003-session-aware-validation.png)


## DET-PS-001 — Encoded PowerShell validation

DET-PS-001 detects selected encoded-command PowerShell execution
patterns using Windows process-creation telemetry.

### Evidence and implementation

- [Detection KQL](detections/DET-PS-001-encoded-powershell.kql)
- [Validation results](detections/reports/DET-PS-001-RESULTS.md)
- [Historical Azure regression](detections/tests/DET-PS-001-regression.kql)
- [Detection-pattern tests](detections/tests/test_det_ps001_patterns.py)
- [Ingestion validation tests](adversary-validation/tests/test_det_ps001.py)

### Verified validation

- One genuine encoded-command event observed and detected in Azure.
- One genuine benign PowerShell event observed and excluded.
- Eighteen synthetic command-line examples passed in Azure.
- Six synthetic full-predicate scenarios passed in Azure.
- Twenty-one ingestion-validation tests passed.
- Two Python detection test methods passed in GitHub Actions.
- Nine separate SOC-LAB-003 Azure KQL regression scenarios passed
  from the main branch using GitHub Actions OIDC.

These results represent different validation scopes.
The synthetic examples are not eighteen genuine Windows executions.

The DET-PS-001 Azure validation results were observed during
interactive testing. No dedicated DET-PS-001 screenshot has
yet been committed to this repository.

## CI workflow
![GitHub Actions Azure KQL regression job succeeded](screenshots/ci/github-actions-success.png)

All threat-hunting matches are investigation candidates observed in lab telemetry, not confirmed incidents. The CI screenshot shows the Azure KQL regression job successful at the time captured, with a Node.js version warning.
