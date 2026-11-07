"""Submit a validated ADV-001 Windows event to Azure Monitor."""

import argparse
import getpass
import importlib.util
import json
import os
import sys
import urllib.parse
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", type=Path)
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    existing_client = repo / "ingestion/scripts/send_test_events.py"

    spec = importlib.util.spec_from_file_location(
        "soc_ingestion_client", existing_client
    )
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)

    tenant = os.environ.get("SOC_TENANT_ID", "").strip()
    client_id = os.environ.get("SOC_CLIENT_ID", "").strip()
    dcr_id = os.environ.get("SOC_DCR_ID", "").strip()
    endpoint = os.environ.get(
        "SOC_INGESTION_ENDPOINT", ""
    ).strip().rstrip("/")

    missing = [
        name for name, value in {
            "SOC_TENANT_ID": tenant,
            "SOC_CLIENT_ID": client_id,
            "SOC_DCR_ID": dcr_id,
            "SOC_INGESTION_ENDPOINT": endpoint,
        }.items() if not value
    ]

    if missing:
        raise SystemExit("Missing configuration: " + ", ".join(missing))

    if not endpoint.startswith("https://"):
        raise SystemExit("Ingestion endpoint must use HTTPS")

    if not dcr_id.startswith("dcr-"):
        raise SystemExit("Invalid DCR immutable ID")

    records = json.loads(args.payload.read_text(encoding="utf-8-sig"))

    if not isinstance(records, list) or len(records) != 1:
        raise SystemExit("Expected exactly one JSON event record")

    record = records[0]

    expected = {
        "TimeGenerated", "EventType", "UserId", "SourceIP",
        "Destination", "Action", "Result", "RiskScore",
        "CorrelationId", "RawData",
    }

    if set(record) != expected:
        raise SystemExit("Payload fields do not match DCR schema")

    if record["EventType"] != "WindowsProcessCreation":
        raise SystemExit("Unexpected event type")

    if record["Action"] != "ProcessCreated":
        raise SystemExit("Unexpected action")

    if not str(record["CorrelationId"]).startswith("ADV-001-"):
        raise SystemExit("Unexpected correlation ID")

    secret = getpass.getpass("Enter Azure client secret (hidden): ")

    if not secret:
        raise SystemExit("Client secret is required")

    token_url = (
        f"https://login.microsoftonline.com/{tenant}"
        "/oauth2/v2.0/token"
    )

    token_body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": secret,
        "grant_type": "client_credentials",
        "scope": "https://monitor.azure.com//.default",
    }).encode("utf-8")

    print("Authenticating with Microsoft Entra...")

    _, response = client.post(
        token_url,
        token_body,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )

    access_token = json.loads(response)["access_token"]
    del secret
    del token_body

    print("PASS: Authentication succeeded")

    stream = "Custom-SOCSecurityEvents"

    url = (
        f"{endpoint}/dataCollectionRules/{dcr_id}"
        f"/streams/{stream}?api-version=2023-01-01"
    )

    print("Submitting one genuine Windows evidence record...")
    print("Correlation ID:", record["CorrelationId"])

    status, _ = client.post(
        url,
        json.dumps(records).encode("utf-8"),
        {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "x-ms-client-request-id": str(uuid.uuid4()),
        },
    )

    print("Azure HTTP status:", status)

    if status in (200, 202, 204):
        print("PASS: Azure Monitor accepted the request")
        print("NEXT: Verify record in Sentinel")
    else:
        raise SystemExit("Unexpected Azure response")


if __name__ == "__main__":
    main()
