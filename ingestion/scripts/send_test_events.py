import getpass
import os
import json
import urllib.parse
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone, timedelta

# Required environment configuration. Never store credentials here.
TENANT_ID = os.environ.get("SOC_TENANT_ID", "").strip()
CLIENT_ID = os.environ.get("SOC_CLIENT_ID", "").strip()
DCR_ID = os.environ.get("SOC_DCR_ID", "").strip()
ENDPOINT = os.environ.get("SOC_INGESTION_ENDPOINT", "").strip().rstrip("/")

STREAM = "Custom-SOCSecurityEvents"

def post(url, body, headers):
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        # Do not print tokens, secrets or request headers.
        print("HTTP error status:", error.code)
        print("Azure error:", error.read().decode("utf-8")[:1200])
        raise SystemExit(1)
    except urllib.error.URLError as error:
        print("Network request failed:", error.reason)
        raise SystemExit(1)

def main():
    required = {
        "SOC_TENANT_ID": TENANT_ID,
        "SOC_CLIENT_ID": CLIENT_ID,
        "SOC_DCR_ID": DCR_ID,
        "SOC_INGESTION_ENDPOINT": ENDPOINT,
    }

    missing = [name for name, value in required.items() if not value]
    if missing:
        raise SystemExit("Missing configuration: " + ", ".join(missing))

    if not ENDPOINT.startswith("https://"):
        raise SystemExit("Ingestion endpoint must use HTTPS")

    if not DCR_ID.startswith("dcr-"):
        raise SystemExit("Invalid DCR ID format")

    secret = getpass.getpass("Enter client secret (hidden): ")
    if not secret:
        raise SystemExit("Empty client secret")

    print("Authenticating with Microsoft Entra...")

    token_url = (
        f"https://login.microsoftonline.com/{TENANT_ID}"
        "/oauth2/v2.0/token"
    )

    token_data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": secret,
        "grant_type": "client_credentials",
        "scope": "https://monitor.azure.com//.default",
    }).encode()

    status, token_response = post(
        token_url,
        token_data,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )

    access_token = json.loads(token_response)["access_token"]
    del secret
    del token_data

    print("PASS: Microsoft Entra authentication succeeded")

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    correlation = str(uuid.uuid4())

    scenarios = [
        ("FailedLogin", "alice.lab", "192.0.2.10",
         "AzurePortal", "SignIn", "Failure", 35),
        ("SuccessfulLogin", "alice.lab", "192.0.2.10",
         "AzurePortal", "SignIn", "Success", 45),
        ("PrivilegeChange", "alice.lab", "192.0.2.10",
         "AzureRBAC", "RoleAssignment", "Success", 80),
        ("SensitiveFileAccess", "alice.lab", "192.0.2.10",
         "FinanceShare", "FileRead", "Success", 70),
        ("DataTransfer", "alice.lab", "192.0.2.10",
         "external-example", "FileTransfer", "Success", 95),
    ]

    events = [
        {
            "TimeGenerated": now,
            "EventType": event_type,
            "UserId": user,
            "SourceIP": ip,
            "Destination": destination,
            "Action": action,
            "Result": result,
            "RiskScore": score,
            "CorrelationId": correlation,
            "RawData": "Synthetic SOC lab test event",
        }
        for event_type, user, ip, destination, action, result, score
        in scenarios
    ]

    # Synthetic activity occurs in five-minute intervals.
    # Preserve the shared correlation ID for investigation.
    base_time = datetime.now(timezone.utc) - timedelta(minutes=20)
    for index, event in enumerate(events):
        event["TimeGenerated"] = (
            base_time + timedelta(minutes=index * 5)
        ).isoformat().replace("+00:00", "Z")

    url = (
        f"{ENDPOINT}/dataCollectionRules/{DCR_ID}"
        f"/streams/{STREAM}?api-version=2023-01-01"
    )

    payload = json.dumps(events).encode("utf-8")

    print("Submitting", len(events), "synthetic events...")

    status, _ = post(
        url,
        payload,
        {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "x-ms-client-request-id": str(uuid.uuid4()),
        },
    )

    print("HTTP status:", status)
    print("Correlation ID:", correlation)

    if status in (200, 202, 204):
        print("PASS: Azure Monitor accepted the event batch")
        print("NEXT: Verify records in Log Analytics")
    else:
        raise SystemExit("Unexpected ingestion response")

if __name__ == "__main__":
    main()
