# Threat Hunting Playbook — Version 1.1

## Scope
Three hypothesis-driven hunting queries over SOCSecurityEvents_CL.
These are read-only investigation queries, not deployed analytics rules.

## HUNT-001: Authentication activity
Hypothesis: A sequence of failed logins followed by a successful
login may indicate credential guessing or account compromise.

ATT&CK candidates:
- T1110 Brute Force, if guessing is supported by evidence
- T1078 Valid Accounts, if credential abuse is established

Triage:
1. Validate event ordering and authentication outcomes.
2. Review source IP, identity, device, MFA and sign-in context.
3. Compare activity with known user behavior.
4. Escalate only after corroborating suspicious access.

## HUNT-002: File access and transfer
Hypothesis: Sensitive file access followed by data transfer
may indicate unauthorized movement of information.

ATT&CK candidate:
- T1537 Transfer Data to Cloud Account, only if external
  cloud-account transfer or sharing is established.

Triage:
1. Verify file sensitivity and actual transfer destination.
2. Establish user authorization and business justification.
3. Determine whether destination is external or approved.
4. Preserve evidence and involve data owners/Legal as required.

## HUNT-003: Privilege changes
Hypothesis: Unusual privilege changes could indicate
persistence or escalation.

ATT&CK candidate:
- T1098 Account Manipulation, subject to evidence of
  unauthorized account or permission modification.

Triage:
1. Identify the initiator and affected identity.
2. Verify approved change tickets and administrative activity.
3. Compare assigned privileges with least-privilege baselines.
4. Investigate related authentication and file-access activity.

## Hunting limitations
- Synthetic telemetry does not establish actual compromise.
- CorrelationId is not independently validated for uniqueness.
- One-hour time buckets can split sequences across boundaries.
- Earliest timestamps can combine unrelated events.
- Missing or inconsistent identifiers can hide activity.
- No device, file hash, file size, or session identity is guaranteed.
- These queries surface candidates, not confirmed attacks.

## Evidence collection
For each hunt record:
- Hypothesis and execution date
- Query version / Git commit
- Time window and available data sources
- Results, relevant timestamps, and supporting evidence
- ATT&CK mapping rationale
- False-positive assessment
- Conclusion and recommended improvements
