# Security Review

## Implemented
- Dedicated Azure ingestion application
- DCR-scoped ingestion permission
- Dedicated GitHub CI query application
- Workspace-scoped Log Analytics Data Reader role
- OIDC federation with branch-restricted trust
- No client secret required for CI login
- Safe analytics-rule deployment defaults
- Detection-as-Code static validation
- Azure-executed synthetic KQL regression testing

## Risks and future hardening
- Verify telemetry provenance and correlation identifiers
- Resolve SOC-LAB-003 mixed-session correlation limitations
- Test cross-session attack coverage
- Add CI negative tests
- Pin GitHub Actions to reviewed commit SHAs
- Review branch protection and repository permissions
- Rotate ingestion credentials according to policy
- Monitor retention, ingestion cost, and log volume
- Verify secrets are not exposed in logs or Git history

## Scope
This is a controlled learning and engineering lab.
It is not approved for production incident detection.
