import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS = []

def check(name, condition):
    print(f'{"PASS" if condition else "FAIL"}: {name}')
    if not condition:
        ERRORS.append(name)

dcr_path = ROOT / "ingestion/dcr-soc-security-events.json"
script_path = ROOT / "ingestion/scripts/send_test_events.py"
fixture_path = ROOT / "tests/fixtures/SOC-LAB-003-test.kql"

template = json.loads(dcr_path.read_text(encoding="utf-8"))
check("One DCR resource", len(template["resources"]) == 1)

resource = template["resources"][0]
props = resource["properties"]

check("Correct resource type",
      resource["type"] == "Microsoft.Insights/dataCollectionRules")
check("Direct ingestion", resource["kind"] == "Direct")
check("Expected DCR name", resource["name"] == "dcr-soc-security-events")

stream = "Custom-SOCSecurityEvents"
columns = props["streamDeclarations"][stream]["columns"]
actual_columns = {c["name"]: c["type"] for c in columns}

expected_columns = {
    "TimeGenerated": "datetime",
    "EventType": "string",
    "UserId": "string",
    "SourceIP": "string",
    "Destination": "string",
    "Action": "string",
    "Result": "string",
    "RiskScore": "int",
    "CorrelationId": "string",
    "RawData": "string",
}

check("Exact input column schema", actual_columns == expected_columns)
check("No duplicate columns", len(columns) == len(actual_columns))

flows = props["dataFlows"]
check("Exactly one data flow", len(flows) == 1)

flow = flows[0]
check("Correct input stream", flow["streams"] == [stream])
check("Correct output stream",
      flow["outputStream"] == "Custom-SOCSecurityEvents_CL")
check("Identity transformation", flow["transformKql"] == "source")

destinations = props["destinations"]["logAnalytics"]
destination_names = {d["name"] for d in destinations}

check("Data flow destination exists",
      len(destinations) == 1
      and flow["destinations"][0] in destination_names)

script = script_path.read_text(encoding="utf-8")
ast.parse(script, filename=str(script_path))

check("Environment-based tenant configuration",
      'os.environ.get("SOC_TENANT_ID"' in script)
check("Environment-based client configuration",
      'os.environ.get("SOC_CLIENT_ID"' in script)
check("Environment-based DCR configuration",
      'os.environ.get("SOC_DCR_ID"' in script)
check("Environment-based endpoint configuration",
      'os.environ.get("SOC_INGESTION_ENDPOINT"' in script)
check("Hidden credential entry", "getpass.getpass" in script)

fixture = fixture_path.read_text(encoding="utf-8")

for scenario in (
    "Positive",
    "MissingPrivilege",
    "WrongOrder",
    "TooSlow",
):
    check(f"Fixture includes {scenario}", f'"{scenario}"' in fixture)

check("Fixture evaluates chronological order",
      "FailedLoginTime < LoginTime" in fixture
      and "FileAccessTime < TransferTime" in fixture)
check("Fixture enforces 30-minute sequence",
      "TransferTime - FailedLoginTime <= 30m" in fixture)
check("Fixture reports PASS/FAIL",
      '"PASS", "FAIL"' in fixture)

if ERRORS:
    raise SystemExit(f"\nINGESTION VALIDATION FAILED: {len(ERRORS)} checks")

print("\nALL INGESTION CONFIGURATION CHECKS PASSED")
print("Live Azure execution: NOT PERFORMED")
