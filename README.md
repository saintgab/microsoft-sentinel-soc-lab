# Microsoft Sentinel SOC & Cloud Detection Engineering Lab

A hands-on Azure security operations project demonstrating cloud security monitoring, KQL detection engineering, alert validation, and incident response using Microsoft Sentinel and Microsoft Defender.

## Project Overview

This lab implements an end-to-end security detection workflow:

Azure Activity Logs → Log Analytics → Microsoft Sentinel → KQL Detection → Security Alert → Incident Investigation

## Technologies

- Microsoft Azure
- Microsoft Sentinel
- Microsoft Defender
- Azure Activity Logs
- Log Analytics
- Kusto Query Language (KQL)
- Azure RBAC
- Azure Policy
- Git and GitHub

## Detection Engineering

### SOC-LAB-001 — High Impact Azure Resource Deletion

**Severity:** Medium

Detects successful deletion of selected Azure resources, including virtual machines, storage accounts, network security groups, and Key Vault vaults.

**Validation:** Live alert and incident successfully tested.

An isolated network security group was intentionally deleted during an authorized security test.

Results:
- Azure Activity recorded the deletion.
- Microsoft Sentinel generated an alert.
- The incident was investigated.
- The incident was resolved as authorized security testing.
- The detection rule was disabled after validation.

[View KQL Detection](detections/SOC-LAB-001-resource-deletion.kql)

### SOC-LAB-002 — Azure RBAC Role Assignment Monitoring

**Severity:** Low

Monitors successful Azure RBAC role-assignment operations.

Results:
- Synthetic KQL testing completed successfully.
- Real Azure Activity logs queried.
- Scheduled analytics rule created.
- Rule remains disabled.
- Live alert generation has not been validated.

This detection monitors role-assignment changes generally; it does not currently distinguish privileged assignments from standard assignments.

[View KQL Detection](detections/SOC-LAB-002-rbac-monitoring.kql)

## Architecture

[View Security Architecture Diagram](docs/architecture.md)

## Security Controls

- Dedicated Azure resource group
- Monthly budget alerts
- Log Analytics daily ingestion cap
- Controlled testing of disposable resources
- No automatic remediation
- Detection rules disabled after testing or development

Budget alerts and ingestion caps do not guarantee a maximum Azure bill.

## Key Learning Outcomes

- Azure cloud security monitoring
- SIEM implementation
- KQL detection development
- Security alert investigation
- Azure RBAC activity analysis
- Microsoft Sentinel analytics rule configuration
- Incident classification and resolution

## Validation Limitations

SOC-LAB-001 was validated using one authorized real-world lab event. SOC-LAB-002 passed synthetic query testing but was not validated through live alert generation.

These detections are educational implementations and require additional tuning before production use.

## Disclaimer

This project was developed in an authorized personal security lab. Sensitive credentials, subscription identifiers, and private information are excluded from the public repository.

## Detection Evidence — Microsoft Sentinel

### SOC-LAB-001: Successful Azure Resource Deletion Detection

The following screenshot demonstrates a real Microsoft Sentinel alert generated during an authorized security test.

![Microsoft Sentinel Resource Deletion Alert](screenshots/sentinel-deletion-alert.png)

### Incident Investigation and Resolution

The resulting case was investigated and closed as authorized security testing.

![Microsoft Defender Closed Security Incident](screenshots/sentinel-resolved-incident.png)

**Validation outcome:** Azure Activity successfully recorded the controlled resource deletion, the scheduled KQL analytics rule generated an alert, and the associated incident was investigated and resolved.

**Note:** Screenshots have been redacted to protect personal identifiers and security-related information.

## Detection-as-Code CI Evidence

This lab includes an automated Detection-as-Code validation pipeline using Python and GitHub Actions.

### Implemented controls

- Version-controlled JSON definitions for SOC-LAB-001 and SOC-LAB-002.
- Validation of required fields, severity, KQL source consistency, and entity mappings.
- Disabled-by-default policy for detection definitions.
- GitHub Actions validation on pushes and pull requests.
- Protected main branch requiring successful detection validation.

### Security gate validation

An intentionally invalid severity was committed to a test branch. GitHub Actions rejected the rule, and the required status check blocked the pull request from merging.

After restoring the valid severity, the pipeline passed and the merge became available.

**Failed validation and blocked merge:**

![Detection-as-Code security gate blocked](screenshots/dac-validation-blocked.png)

**Successful validation after remediation:**

![Detection-as-Code validation passed](screenshots/dac-validation-passed.png)

### Scope and limitations

These are local Detection-as-Code rule definitions, not yet complete deployable Microsoft Sentinel ARM templates.

The CI pipeline performs offline validation. It does not deploy analytics rules to Azure or verify live Sentinel alert generation.

The original Sentinel detection evidence remains documented separately.

## Operations and validation documentation

- [Architecture](docs/project-architecture.md)
- [Operations runbook](docs/operations-runbook.md)
- [Security review](docs/security-review.md)
- [SOC-LAB-003 correlation findings](docs/SOC-LAB-003-correlation-validation.md)

The lab includes static validation and an Azure-authenticated
KQL regression workflow covering nine synthetic scenarios.

The custom analytics rules remain disabled.
The session-aware candidate has not been deployed.
