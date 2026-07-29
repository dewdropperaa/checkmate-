# Sync Vercel production API URL after Render deploy (no Docker required).
param(
  [Parameter(Mandatory = $true)]
  [string]$ApiUrl
)

$ApiUrl = $ApiUrl.Trim().TrimEnd("/")
if ($ApiUrl -notmatch "^https://") {
  Write-Error "ApiUrl must be https://..."
  exit 1
}

Push-Location $PSScriptRoot\..\web
try {
  npx --yes vercel@latest link --project checkmate.app --yes | Out-Null
  $ApiUrl | npx --yes vercel@latest env add NEXT_PUBLIC_API_BASE_URL production --force
  Write-Host "Set NEXT_PUBLIC_API_BASE_URL=$ApiUrl on checkmate.app (production)."
  Write-Host "Run: npx vercel deploy --prod  (from repo root or web per your Vercel root)"
}
finally {
  Pop-Location
}
