# Post-deploy smoke test for OWASP ZAP + backend (Windows PowerShell).
# See smoke_zap_deploy.sh for the full checklist.
#
# Usage (from backend/):
#   $env:ZAP_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
#   $env:AUTHORIZED_TARGETS = "example.com"
#   docker compose up -d --build
#   powershell -File scripts/smoke_zap_deploy.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$ApiBase = if ($env:API_BASE) { $env:API_BASE } else { "http://127.0.0.1:8000" }
$SmokeTarget = if ($env:SMOKE_TARGET) { $env:SMOKE_TARGET } else { "https://example.com" }
$ZapTimeout = if ($env:ZAP_HEALTH_TIMEOUT_SECS) { [int]$env:ZAP_HEALTH_TIMEOUT_SECS } else { 300 }
$ScanTimeout = if ($env:SCAN_TIMEOUT_SECS) { [int]$env:SCAN_TIMEOUT_SECS } else { 900 }
$ComposeFile = if ($env:COMPOSE_FILE) { $env:COMPOSE_FILE } else { "docker-compose.yml" }

function Write-Smoke([string]$Message) { Write-Host "[smoke-zap] $Message" }
function Fail-Smoke([string]$Message) { throw "[smoke-zap] ERROR: $Message" }

function Get-AuthHeaders {
    $h = @{ "Content-Type" = "application/json" }
    if ($env:API_KEY) { $h["X-API-Key"] = $env:API_KEY }
    if ($env:FIREBASE_ID_TOKEN) { $h["Authorization"] = "Bearer $($env:FIREBASE_ID_TOKEN)" }
    return $h
}

Write-Smoke "Waiting for zap healthy (timeout ${ZapTimeout}s)..."
$deadline = (Get-Date).AddSeconds($ZapTimeout)
while ($true) {
    $ps = docker compose -f $ComposeFile ps zap 2>$null | Out-String
    if ($ps -match "healthy") {
        Write-Smoke "ZAP container is healthy"
        break
    }
    if ((Get-Date) -ge $deadline) {
        docker compose -f $ComposeFile logs --tail=80 zap
        Fail-Smoke "ZAP did not become healthy within ${ZapTimeout}s"
    }
    Start-Sleep -Seconds 5
}

Write-Smoke "Probing GET $ApiBase/health for zap_ready..."
$deadline = (Get-Date).AddSeconds(120)
while ($true) {
    try {
        $health = Invoke-RestMethod -Uri "$ApiBase/health" -Method Get
        if ($health.zap_ready -or $health.toolchain.zap_ready) {
            Write-Smoke "Backend reports ZAP ready"
            break
        }
    } catch { }
    if ((Get-Date) -ge $deadline) {
        Fail-Smoke "GET /health did not report zap_ready within 120s"
    }
    Start-Sleep -Seconds 3
}

$headers = Get-AuthHeaders
Write-Smoke "Starting minimal scan against $SmokeTarget..."
try {
    $scan = Invoke-RestMethod -Uri "$ApiBase/scan" -Method Post -Headers $headers -Body (@{
        target = $SmokeTarget
        confirmed_authorized = $true
    } | ConvertTo-Json)
} catch {
    Fail-Smoke "POST /scan failed — is $SmokeTarget on AUTHORIZED_TARGETS? $_"
}
$scanId = $scan.scan_id
Write-Smoke "scan_id=$scanId"

$targetQ = [uri]::EscapeDataString($SmokeTarget)
Write-Smoke "Polling scan (timeout ${ScanTimeout}s)..."
$deadline = (Get-Date).AddSeconds($ScanTimeout)
$finalStatus = ""
while ($true) {
    $status = Invoke-RestMethod -Uri "$ApiBase/scan/${scanId}/status?target=$targetQ" -Method Get -Headers $headers
    $finalStatus = [string]$status.status
    if ($finalStatus -in @("awaiting_approval", "waiting_for_approval", "paused") -or $status.awaiting_approval) {
        $planned = @($status.planned_active_tests)
        if (-not $planned -or $planned.Count -eq 0) { $planned = @("zap") }
        Write-Smoke "Approving active tools: $($planned -join ',')"
        try {
            Invoke-RestMethod -Uri "$ApiBase/scan/${scanId}/approve?target=$targetQ" -Method Post -Headers $headers -Body (@{
                approved = $true
                approved_tools = $planned
            } | ConvertTo-Json) | Out-Null
        } catch {
            Write-Smoke "Approve call non-success (may already be running)"
        }
    }
    if ($finalStatus -in @("scored", "completed", "complete", "report_ready", "failed", "error", "rejected")) {
        break
    }
    if ((Get-Date) -ge $deadline) {
        Fail-Smoke "Scan did not finish within ${ScanTimeout}s (status=$finalStatus)"
    }
    Start-Sleep -Seconds 5
}

Write-Smoke "Final status=$finalStatus"
if ($finalStatus -in @("failed", "error", "rejected")) {
    Fail-Smoke "Scan ended in terminal failure state: $finalStatus"
}

$report = Invoke-RestMethod -Uri "$ApiBase/scan/${scanId}/report?target=$targetQ" -Method Get -Headers $headers
$cov = $report.severity_scores.scan_coverage
$meta = $report.detection_metadata
$errors = @{}
if ($meta -and $meta.errors) { $errors = $meta.errors }
$notes = @()
if ($cov -and $cov.coverage_notes) { $notes += $cov.coverage_notes }
if ($meta -and $meta.coverage_notes) { $notes += $meta.coverage_notes }
$zapErr = ""
if ($errors.active_zap) { $zapErr = [string]$errors.active_zap }
elseif ($errors.zap) { $zapErr = [string]$errors.zap }

$joined = ($notes | ForEach-Object { [string]$_ }) -join " "
if ($joined -match "ZAP unavailable") {
    Fail-Smoke "ZAP was skipped as unavailable"
}
if ($zapErr -match "unreachable|unavailable|connection refused") {
    Fail-Smoke "ZAP connectivity failure: $zapErr"
}

Write-Smoke "PASS: ZAP healthy, /health zap_ready, scan completed through active detection"
