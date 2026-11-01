import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "dac" / "rules"
DETECTIONS = (ROOT / "detections").resolve()
SEVERITIES = {"Informational", "Low", "Medium", "High"}
OPERATORS = {"GreaterThan", "LessThan", "Equal", "NotEqual"}

def validate(path):
    errors = []

    try:
        rule = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"Invalid JSON: {exc}"]

    if not isinstance(rule, dict):
        return ["Rule must be a JSON object"]

    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not re.fullmatch(
        r"SOC-LAB-\d{3}", rule_id
    ):
        errors.append("Invalid or missing rule ID")
    elif path.stem != rule_id:
        errors.append("Filename does not match rule ID")

    if rule.get("kind") != "Scheduled":
        errors.append("Rule kind must be Scheduled")

    props = rule.get("properties")
    if not isinstance(props, dict):
        return errors + ["Missing properties object"]

    for field in ("displayName", "description"):
        if not isinstance(props.get(field), str) or not props[field].strip():
            errors.append(f"Missing or empty {field}")

    if props.get("severity") not in SEVERITIES:
        errors.append("Invalid severity")

    if props.get("enabled") is not False:
        errors.append("Security policy: rule must be disabled")

    source_file = rule.get("sourceFile")
    query = props.get("query")

    if not isinstance(source_file, str):
        errors.append("Missing sourceFile")
    else:
        source = (ROOT / source_file).resolve()

        if not source.is_relative_to(DETECTIONS):
            errors.append("sourceFile must be inside detections/")
        elif not source.is_file():
            errors.append("Original KQL file does not exist")
        elif not isinstance(query, str) or query != source.read_text(
            encoding="utf-8"
        ):
            errors.append("KQL does not match original source")

    if not isinstance(query, str) or not query.strip():
        errors.append("Missing KQL query")
        query = ""

    for field in ("queryFrequency", "queryPeriod"):
        value = props.get(field)
        if not isinstance(value, str) or not re.fullmatch(
            r"PT[1-9]\d*[MH]", value
        ):
            errors.append(f"Invalid {field}")

    if props.get("triggerOperator") not in OPERATORS:
        errors.append("Invalid triggerOperator")

    threshold = props.get("triggerThreshold")
    if type(threshold) is not int or threshold < 0:
        errors.append("Invalid triggerThreshold")

    for field in ("tactics", "techniques"):
        value = props.get(field)
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item.strip()
            for item in value
        ):
            errors.append(f"Invalid {field}")

    mappings = props.get("entityMappings")

    if not isinstance(mappings, list) or not mappings:
        errors.append("Missing entityMappings")
    else:
        project_match = re.search(
            r"(?ims)^\s*\|\s*project\s+(.*?)(?=^\s*\||\Z)",
            query
        )

        projected = (
            set(re.findall(r"\b[A-Za-z_]\w*\b", project_match.group(1)))
            if project_match else set()
        )

        if not project_match:
            errors.append("Expected a KQL project statement")

        for mapping in mappings:
            if not isinstance(mapping, dict):
                errors.append("Invalid entity mapping")
                continue

            if not isinstance(mapping.get("entityType"), str):
                errors.append("Missing entityType")

            fields = mapping.get("fieldMappings")

            if not isinstance(fields, list) or not fields:
                errors.append("Missing fieldMappings")
                continue

            for field in fields:
                if not isinstance(field, dict):
                    errors.append("Invalid field mapping")
                    continue

                column = field.get("columnName")
                identifier = field.get("identifier")

                if not isinstance(identifier, str) or not identifier:
                    errors.append("Missing entity identifier")

                if not isinstance(column, str) or column not in projected:
                    errors.append(f"Unrecognized projected column: {column}")

    return errors


def main():
    files = sorted(RULES.glob("*.json"))

    if not files:
        print("FAIL: No detection rules found")
        return 1

    failures = 0

    for path in files:
        errors = validate(path)

        if errors:
            failures += 1
            print(f"FAIL: {path.name}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS: {path.name}")

    print(f"\nValidated {len(files)} detection rules.")

    if failures:
        print(f"FAILED: {failures} rules")
        return 1

    print("ALL DETECTION-AS-CODE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
