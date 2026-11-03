# SOC Lab Operations Runbook

## Environment
Resource group: rg-sentinel-soc-lab
Workspace: law-sentinel-soc-lab
Custom table: SOCSecurityEvents_CL
Data collection rule: dcr-soc-security-events

## Monitoring
1. Check GitHub Actions workflow results.
2. Check ingestion health and timestamps.
3. Review resource configuration and RBAC assignments.
4. Review workspace ingestion volume and cost.
5. Verify analytics rules remain in their approved state.

## Investigation
1. Identify suspicious events and establish the timeline.
2. Validate user, source IP, and correlation identifiers.
3. Investigate related sessions and supporting telemetry.
4. Assess false positives and expected administrative activity.
5. Record findings and preserve evidence.
6. Follow approved incident escalation procedures.

## Safe rollback
1. Identify the last known-good Git commit.
2. Revert the affected changes.
3. Rerun local and Azure regression tests.
4. Review ARM what-if before an approved redeployment.
5. Confirm deployed rule settings after remediation.

## Safety
Lab analytics rules remain disabled.
Incident creation remains disabled.
Do not enable automated response without further testing.
