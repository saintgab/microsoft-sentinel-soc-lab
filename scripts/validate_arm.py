import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS = []

RULES = ["SOC-LAB-001", "SOC-LAB-002"]

FIELDS = [
    "displayName", "description", "severity",
    "query", "queryFrequency", "queryPeriod",
    "triggerOperator", "triggerThreshold",
    "suppressionEnabled", "suppressionDuration",
    "tactics", "techniques", "entityMappings"
]

ids = set()

for rule in RULES:
    try:
        source = json.loads(
            (ROOT / "dac/rules" / f"{rule}.json").read_text()
        )
        arm = json.loads(
            (ROOT / "arm" / f"{rule}.json").read_text()
        )

        source_props = source.get("properties", source)
        resources = arm["resources"]

        assert len(resources) == 1, "Expected one ARM resource"

        resource = resources[0]
        props = resource["properties"]

        assert resource["type"] == "Microsoft.SecurityInsights/alertRules"
        assert resource["apiVersion"] == "2022-11-01"
        assert resource["kind"] == "Scheduled"
        assert resource["name"] == "[parameters('ruleId')]"
        assert arm["parameters"]["workspaceName"]["type"] == "string"

        rule_id = arm["parameters"]["ruleId"]["defaultValue"]
        uuid.UUID(rule_id)

        assert rule_id not in ids, "Duplicate rule ID"
        ids.add(rule_id)

        assert props["enabled"] is False, "Rule must be disabled"
        assert props["incidentConfiguration"]["createIncident"] is False, (
            "Incident creation must be disabled"
        )

        for field in FIELDS:
            if field in source_props:
                assert props.get(field) == source_props[field], (
                    f"{field} differs from source"
                )

        allowed = set(FIELDS) | {
            "enabled", "incidentConfiguration"
        }

        extra = set(props) - allowed
        assert not extra, f"Unexpected ARM properties: {sorted(extra)}"

        missing_source = set(source_props) - allowed
        assert not missing_source, (
            f"Source properties not checked: {sorted(missing_source)}"
        )

        print(f"PASS: {rule} ARM safety and source consistency")

    except (AssertionError, KeyError, ValueError, OSError) as exc:
        ERRORS.append(f"{rule}: {exc}")
        print(f"FAIL: {rule}: {exc}")

if ERRORS:
    print(f"\nARM VALIDATION FAILED: {len(ERRORS)} issue(s)")
    sys.exit(1)

print("\nALL ARM SECURITY CHECKS PASSED")
print("Azure schema/deployment validation: NOT PERFORMED")
