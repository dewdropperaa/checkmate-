# Security Policy

## Authorized use only

**checkmate must only be used against targets you own or have explicit, written authorization to test.**

Unauthorized scanning may violate computer fraud and abuse laws, service terms, and organizational policy. Operators are solely responsible for ensuring they have proper authorization before queuing any scan.

## Scope enforcement

All scan activity is gated by an explicit allowlist configured via the `AUTHORIZED_TARGETS` environment variable (see `backend/.env.example`).

- Targets are normalized (hostname extraction, lowercase, optional port) before comparison.
- **Every API endpoint** calls `core.scope.enforce_scope()` on the supplied target **before** any other processing.
- Requests for targets not on the allowlist receive **HTTP 403** with `error: target_not_authorized`.
- An empty allowlist denies all targets.

There is no bypass, wildcard, or “scan anything” mode in this scaffold. Expanding scope requires deliberately updating configuration.

### Configuring the allowlist

```env
AUTHORIZED_TARGETS=example.com,https://app.example.com
```

Only list domains and URLs that are in scope for your engagement.

## Secret handling

- API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) and other secrets are loaded from the environment via `pydantic-settings`.
- **Never** commit real secrets. Use `.env` locally (gitignored) and your platform’s secret manager in production.
- `.env.example` contains placeholders only.
- Settings fields holding secrets use `repr=False` to reduce accidental exposure in logs.

## ZAP deployment

- Production Compose does **not** publish ZAP’s API on a host port. Backend
  reaches it only as `http://zap:8080` on the private Docker network.
- `api.disablekey=false` and a required `ZAP_API_KEY` are mandatory in Compose
  / production. Never ship `api.disablekey=true` outside local `start_zap.ps1`.
- ZAP’s REST API has no TLS. If ZAP is ever moved off the Compose network,
  wrap the hop (private network, mTLS sidecar, or SSH tunnel) — do not expose
  raw HTTP on the public internet.
- Image pin: `ghcr.io/zaproxy/zaproxy:2.17.0@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2`
  (digest-pinned for supply-chain reproducibility; upgrade deliberately after
  testing; do not use `:latest` / `:stable` in production).
- Post-deploy: `backend/scripts/smoke_zap_deploy.sh` (or `.ps1`).

## Logging

- Logs are emitted as structured JSON including a per-request `request_id` (also returned as `X-Request-ID`).
- Do not log secrets, full authorization headers, or raw credentials.
- Production deployments should ship logs to a restricted, access-controlled sink.
- ZAP container logs use the same `json-file` driver as the backend (`docker compose logs zap`).
- Distinct scan lifecycle events: `zap_unreachable`, `zap_scan_timeout`, `zap_scan_completed`, `zap_skipped_unavailable`.

The Chrome extension requests minimal permissions:

- `activeTab` — read the current tab URL when the user opens the popup
- `storage` — remember the last authorized target locally
- `host_permissions: http://localhost:8000/*` — communicate with the local API only

No broad `<all_urls>` host permission is requested. Content scripts match `http`/`https` pages for future in-page integration; they perform no scanning in this scaffold.

## Reporting vulnerabilities

If you discover a security issue in checkmate itself, report it privately to the project maintainers. Do not disclose publicly until a fix is available.

## Roadmap security notes

Future phases will add external CLI tool wrappers (`BaseSecurityTool.run()`). Those integrations must:

- Never invoke subprocesses without prior scope validation
- Pass only authorized targets to tools
- Run tool binaries from the isolated `/opt/tools` mount with least privilege
- Sanitize and bound tool output before agent consumption
