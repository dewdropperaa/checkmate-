#!/bin/sh
set -e

echo "==> Validating security tool chain before accepting scans..."
python -c "from core.config import get_settings; from core.toolchain import validate_toolchain_at_startup; validate_toolchain_at_startup(get_settings())"

echo "==> Syncing nuclei templates..."
/opt/tools/nuclei -update-templates -silent || true

echo "==> Starting API server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
