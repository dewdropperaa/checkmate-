#!/bin/sh
set -e
# OWASP ZAP daemon for Render private service (internal network only).
exec zap.sh -daemon \
  -host 0.0.0.0 \
  -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=false \
  -config "api.key=${ZAP_API_KEY:?ZAP_API_KEY must be set}"
