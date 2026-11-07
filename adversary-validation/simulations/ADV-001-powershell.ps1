# ADV-001: Benign PowerShell execution telemetry test
# MITRE ATT&CK T1059.001
# Authorized lab endpoint only

$ErrorActionPreference = "Stop"

$TestId = "ADV-001-" + (Get-Date -Format "yyyyMMdd-HHmmss")

Write-Host "Starting ADV-001"
Write-Host "Test ID: $TestId"

$Arguments = "-NoProfile -NonInteractive -Command `"Write-Output '$TestId'; Get-Date`""

$Process = Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList $Arguments `
    -Wait `
    -PassThru

if ($Process.ExitCode -ne 0) {
    throw "Simulation failed with exit code $($Process.ExitCode)"
}

Write-Host "Simulation completed successfully."
Write-Host "Search Security Event ID 4688 for $TestId"
