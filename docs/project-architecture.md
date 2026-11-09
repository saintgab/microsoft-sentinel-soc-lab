# Microsoft Sentinel SOC Lab Architecture

## Telemetry pipeline
Synthetic test generator or converted genuine Windows Event 4688 evidence
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

## Telemetry provenance

The custom table contains controlled lab test events.

DET-PS-001 positive and negative validation used genuine Windows
Security Event 4688 records, manually exported, converted into
the existing ingestion schema, and submitted using the Azure
Monitor Logs Ingestion API.

Other SOC-LAB-003 regression scenarios use synthetic fixtures.
These sources are not interchangeable, and continuous production
telemetry collection has not been demonstrated.
