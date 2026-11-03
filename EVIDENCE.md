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

## CI workflow
![GitHub Actions Azure KQL regression job succeeded](screenshots/ci/github-actions-success.png)

All threat-hunting matches are investigation candidates observed in lab telemetry, not confirmed incidents. The CI screenshot shows the Azure KQL regression job successful at the time captured, with a Node.js version warning.
