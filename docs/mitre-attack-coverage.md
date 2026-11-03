# MITRE ATT&CK Hunting Coverage

| Hunt | Technique | Tactic | Evidence required |
|---|---|---|---|
| HUNT-001 | T1110 Brute Force | Credential Access | Repeated credential guessing |
| HUNT-001 | T1078 Valid Accounts | Multiple tactics | Evidence of unauthorized credential use |
| HUNT-002 | T1537 Transfer Data to Cloud Account | Exfiltration | Data shared or transferred to another cloud account |
| HUNT-003 | T1098 Account Manipulation | Persistence / Privilege Escalation | Account or permission modification |

## Coverage limitations

These are hypothesis-based ATT&CK mappings, not validated
detections of each technique.

HUNT-001 requires corroboration of credential guessing or abuse.

HUNT-002 only maps to T1537 when evidence establishes transfer
to another cloud account. Generic DataTransfer events do not
prove cloud exfiltration.

HUNT-003 requires evidence that a privilege change represents
relevant account manipulation.

Current data source: SOCSecurityEvents_CL.
All three hunts use synthetic/custom lab telemetry.
