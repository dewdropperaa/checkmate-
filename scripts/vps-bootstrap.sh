#!/usr/bin/env bash
# Bootstrap checkmate API + ZAP on a Linux VPS (Oracle Cloud Always Free ARM, etc.)
# Run as root or with sudo on Ubuntu 22.04/24.04 aarch64 or x86_64.
set -euo pipefail

REPO_URL="${CHECKMATE_REPO_URL:-https://github.com/dewdropperaa/checkmate-.git}"
INSTALL_DIR="${CHECKMATE_INSTALL_DIR:-/opt/checkmate}"
DOMAIN="${CHECKMATE_API_DOMAIN:-}"

echo "==> Installing Docker..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

if ! docker compose version >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y docker-compose-plugin git curl
fi

echo "==> Cloning checkmate..."
mkdir -p "$(dirname "$INSTALL_DIR")"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" pull --ff-only
else
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR/backend"

if [[ ! -f .env ]]; then
  echo "==> Create backend/.env from your local machine values:"
  echo "    APP_ENV=hosted"
  echo "    CLOUD_SCANNING_ENABLED=true"
  echo "    CLOUD_SCAN_PROFILE=full"
  echo "    REQUIRE_FIREBASE_AUTH=true"
  echo "    ZAP_API_KEY=<generate random>"
  echo "    FIREBASE_PROJECT_ID=..."
  echo "    FIREBASE_CREDENTIALS_JSON=..."
  echo "    CREDENTIALS_MASTER_KEY=..."
  echo "    PUBLIC_APP_URL=https://checkmateapp-nine.vercel.app"
  cp .env.example .env
  echo "Edit $INSTALL_DIR/backend/.env then re-run this script."
  exit 1
fi

if ! grep -q '^ZAP_API_KEY=.' .env; then
  echo "ERROR: Set ZAP_API_KEY in backend/.env"
  exit 1
fi

echo "==> Building and starting API + ZAP (this may take 10–20 min on first run)..."
docker compose -f docker-compose.yml up -d --build

echo "==> Waiting for health..."
for i in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8000/health | grep -q '"zap_ready": true'; then
    echo "API + ZAP ready."
    break
  fi
  sleep 5
done

curl -s http://127.0.0.1:8000/health | head -c 500 || true
echo ""

if [[ -n "$DOMAIN" ]]; then
  echo "==> Installing Caddy for HTTPS on $DOMAIN..."
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y caddy
  cat >/etc/caddy/Caddyfile <<EOF
$DOMAIN {
  reverse_proxy 127.0.0.1:8000
}
EOF
  systemctl reload caddy
  echo "HTTPS API: https://$DOMAIN"
  echo "Run: ./scripts/deploy-production-api.ps1 -RenderApiUrl https://$DOMAIN"
else
  echo ""
  echo "Set CHECKMATE_API_DOMAIN=api.yourdomain.com and re-run for automatic HTTPS,"
  echo "or use Cloudflare Tunnel — see docs/LAUNCH_ZAP_ORACLE.md"
  echo "API (HTTP only): http://$(curl -s ifconfig.me 2>/dev/null || echo YOUR_VM_IP):8000"
fi
