# One-time production API setup: Render blueprint + Vercel wiring.
# Oracle VPS + Cloudflare Tunnel: pass -RenderApiUrl https://….trycloudflare.com
param(
  [string]$RenderApiUrl,

  [switch]$Paid,

  [switch]$SkipVercelSync,

  [switch]$AllowTunnel
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$backendEnv = Join-Path $repoRoot "backend\.env"

function Read-DotEnvValue([string]$path, [string]$key) {
  if (-not (Test-Path $path)) { return $null }
  foreach ($line in Get-Content $path) {
    if ($line -match "^\s*$key\s*=\s*(.*)$") {
      return $Matches[1].Trim().Trim('"').Trim("'")
    }
  }
  return $null
}

$firebaseProject = Read-DotEnvValue $backendEnv "FIREBASE_PROJECT_ID"
$credsPath = Read-DotEnvValue $backendEnv "FIREBASE_CREDENTIALS_PATH"
$creatorEmails = Read-DotEnvValue $backendEnv "CREATOR_EMAILS"

Write-Host ""
Write-Host "=== checkmate production API (Render) ===" -ForegroundColor Cyan
if ($Paid) {
  Write-Host "Mode: PAID (render.starter.yaml) - credit card required, cloud scans enabled"
  Write-Host "In Render: New -> Blueprint -> use render.starter.yaml (or rename file to render.yaml)"
} else {
  Write-Host "Mode: FREE Render - auth/dashboard ONLY (no ZAP). For ZAP see docs/LAUNCH_ZAP_ORACLE.md"
}
Write-Host ""
Write-Host "1. Push this repo to GitHub (if needed)."
Write-Host "2. Render Dashboard -> New -> Web Service -> connect github.com/dewdropperaa/checkmate-"
Write-Host "   Root dir: backend | Runtime: Python | Plan: Free"
Write-Host "   Build: pip install -r requirements.txt"
Write-Host "   Start: uvicorn app.main:app --host 0.0.0.0 --port `$PORT"
Write-Host "   Health: /health"
Write-Host "   Full steps: docs/LAUNCH_FREE.md"
Write-Host "3. Set env vars on checkmate-api:"
Write-Host "   FIREBASE_PROJECT_ID = $firebaseProject"

if ($credsPath -and (Test-Path $credsPath)) {
  Write-Host "   FIREBASE_CREDENTIALS_JSON = paste contents of:"
  Write-Host "     $credsPath"
  Write-Host "   (Render: one line, no newlines - PowerShell: (Get-Content path -Raw))"
} else {
  Write-Host "   FIREBASE_CREDENTIALS_JSON = (service account JSON, one line)"
}

if ($creatorEmails) {
  Write-Host "   CREATOR_EMAILS = $creatorEmails"
}
Write-Host "   CREDENTIALS_MASTER_KEY = (from backend/.env or generate Fernet key)"

Write-Host "4. Wait until checkmate-api is Live."
Write-Host "   Test: https://YOUR-SERVICE.onrender.com/health"
Write-Host ""

if (-not $RenderApiUrl) {
  Write-Host "When Live, re-run with your Render URL:" -ForegroundColor Yellow
  Write-Host "  .\scripts\deploy-production-api.ps1 -RenderApiUrl https://YOUR-SERVICE.onrender.com"
  Write-Host ""
  exit 0
}

$RenderApiUrl = $RenderApiUrl.Trim().TrimEnd("/")
$isTunnel = $RenderApiUrl -match "loca\.lt|localtunnel\.me|ngrok|trycloudflare\.com"
if ($isTunnel -and -not $AllowTunnel) {
  Write-Host "Cloudflare/quick tunnel detected. Re-run with -AllowTunnel for Oracle VPS setup." -ForegroundColor Yellow
}

try {
  $health = Invoke-RestMethod -Uri "$RenderApiUrl/health" -TimeoutSec 60
  Write-Host "API health: $($health.status) (zap=$($health.zap_ready))" -ForegroundColor Green
} catch {
  Write-Error "Cannot reach $RenderApiUrl/health - check tunnel/API is running."
}

if (-not $SkipVercelSync) {
  $syncArgs = @{
    ApiUrl = $RenderApiUrl
  }
  if ($AllowTunnel -or $isTunnel) {
    $syncArgs.AllowDevTunnel = $true
  }
  & (Join-Path $PSScriptRoot "sync-vercel-api-url.ps1") @syncArgs
  Push-Location $repoRoot
  try {
    npx --yes vercel@latest deploy --prod --yes
  } finally {
    Pop-Location
  }
}

Write-Host ""
Write-Host "Production is wired. Kill local uvicorn / localtunnel / ZAP - they are not needed." -ForegroundColor Green
