# Microsoft Sentinel SOC Lab Architecture

## Telemetry pipeline
Python test event generator
  -> Microsoft Entra authentication
  -> Azure Monitor Logs Ingestion API
  -> Data Collection Rule
  -> SOCSecurityEvents_CL
  -> Log Analytics / Microsoft Sentinel

## Detection-as-Code pipeline
Local Git repository
  -> GitHub
  -> GitHub Actions static validation
  -> GitHub OIDC authentication
  -> Workspace-scoped Azure query identity
  -> Azure-executed KQL regression tests

## Analytics rules
SOC-LAB-001: High Impact Azure Resource Deletion
SOC-LAB-002: Azure RBAC Role Assignment Monitoring
SOC-LAB-003: Multi-Stage Suspicious Account Activity

## Testing
Four original regression scenarios passed.
Three repeated-event scenarios passed.
Two session-aware candidate scenarios passed.

Nine synthetic regression assertions are automated.

## Known limitation
SOC-LAB-003 can correlate unrelated sessions sharing
CorrelationId, UserId, and SourceIP.

A session-aware candidate passed synthetic testing but has
not been deployed. The current custom table lacks SessionId.

## Operational safeguards
- Workspace-scoped read-only CI access
- Separate ingestion and query identities
- Disabled custom analytics rules
- Disabled incident creation
- Version-controlled detection and validation code
