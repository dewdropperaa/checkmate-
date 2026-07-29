# Start OWASP ZAP daemon for local checkmate development ONLY.
# Uses api.disablekey=true — NEVER use this configuration in production.
# Production Compose starts ZAP with api.disablekey=false and a required ZAP_API_KEY.
# Prefer Docker for local API access:
#   docker compose -f docker-compose.yml -f docker-compose.dev.yml up zap
$ErrorActionPreference = "Stop"
Write-Warning "DEV ONLY: starting ZAP with api.disablekey=true on 127.0.0.1:8080"

$zapDir = "C:\Program Files\ZAP\Zed Attack Proxy"
$zapBat = Join-Path $zapDir "zap.bat"
if (-not (Test-Path $zapBat)) {
  throw "ZAP not found. Install with: winget install --id ZAP.ZAP -e"
}

Write-Host "Starting ZAP daemon on http://127.0.0.1:8080 ..."
Start-Process -FilePath $zapBat -ArgumentList @(
  "-daemon",
  "-silent",
  "-host", "127.0.0.1",
  "-port", "8080",
  "-config", "api.disablekey=true",
  "-config", "api.addrs.addr.name=.*",
  "-config", "api.addrs.addr.regex=true"
) -WorkingDirectory $zapDir -WindowStyle Hidden

for ($i = 1; $i -le 48; $i++) {
  Start-Sleep -Seconds 5
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:8080/JSON/core/view/version/" -UseBasicParsing -TimeoutSec 5
    if ($r.StatusCode -eq 200) {
      Write-Host "ZAP is ready: $($r.Content)"
      exit 0
    }
  } catch {
    Write-Host "Waiting for ZAP... ($i/48)"
  }
}
throw "ZAP did not become ready within ~4 minutes"
