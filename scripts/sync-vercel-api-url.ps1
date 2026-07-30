# Point Vercel production at your cloud FastAPI origin (Render, custom domain).
# Refuses loca.lt / ngrok — production must not depend on your laptop.
param(
  [Parameter(Mandatory = $true)]
  [string]$ApiUrl,

  [switch]$AllowDevTunnel
)

$ApiUrl = $ApiUrl.Trim().TrimEnd("/")
if ($ApiUrl -notmatch "^https://") {
  Write-Error "ApiUrl must be https://..."
  exit 1
}

$isTunnel = $ApiUrl -match "loca\.lt|localtunnel\.me|ngrok|trycloudflare\.com"
if ($isTunnel -and -not $AllowDevTunnel) {
  Write-Error @"
Production cannot use a dev tunnel ($ApiUrl).
Deploy the cloud API first:  .\scripts\deploy-production-api.ps1
Then pass your Render URL, e.g. https://checkmate-api.onrender.com
"@
  exit 1
}

Push-Location $PSScriptRoot\..\web
try {
  npx --yes vercel@latest link --project checkmate.app --yes | Out-Null
  $ApiUrl | npx --yes vercel@latest env add API_BASE_URL production --force
  $ApiUrl | npx --yes vercel@latest env add NEXT_PUBLIC_API_BASE_URL production --force
  Write-Host "Set API_BASE_URL and NEXT_PUBLIC_API_BASE_URL=$ApiUrl on checkmate.app (production)."
  Write-Host "Run: npx vercel deploy --prod  (from repo root)"
}
finally {
  Pop-Location
}
