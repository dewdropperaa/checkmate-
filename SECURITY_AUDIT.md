# SECURITY_AUDIT

Date: 2026-07-06
Scope reviewed: `backend/`

## What Was Checked

1. **Dangerous execution/deserialization patterns**
   - Searched backend for `shell=True`, `eval(`, `exec(`, and `pickle.loads`.
   - Result: none found in executable code paths.
   - Existing subprocess layer already uses `asyncio.create_subprocess_exec` (argument list, no shell).

2. **Scope enforcement before tool execution**
   - Verified API routes that accept target input call `enforce_scope(...)` in `app/main.py`.
   - Verified each tool wrapper re-validates target scope with `validate_scope(...)` before network/tool execution.
   - Confirmed orchestrator also performs graph-level scope check (`check_scope` node) before recon/detection.

3. **Secrets management**
   - Verified API keys and tool credentials are read via environment settings in `core/config.py`.
   - No hardcoded API keys found in backend code.
   - Confirmed `.env` is excluded in `.gitignore` (root and `backend/.env` patterns present).

4. **Unbounded scan launch prevention**
   - Added in-memory `/scan` controls in `app/main.py`:
     - Sliding-window rate limit per client identity (IP or `X-API-Key`)
     - Per-client concurrent scan cap
     - Global concurrent scan cap
   - Limit slots are released automatically when scan tasks finish.

5. **Subprocess timeout + process-group kill enforcement**
   - Hardened Windows kill path in `tools/base.py` to use `taskkill /T /F` for process-tree termination.
   - Added a real-process enforcement test (`backend/tests/test_subprocess_enforcement.py`) that:
     - Starts a parent process that spawns a child sleeper
     - Forces timeout through `run_subprocess_safely(...)`
     - Verifies the spawned child process is no longer alive

## Additional Hardening Applied

- Implemented report artifact generation (`json`, `md`, `html`) under `backend/reports/{scan_id}/`.
- Added format-specific report serving endpoint: `GET /scan/{id}/report/{format}`.
- Hardened Docker ZAP defaults:
  - Enabled API key requirement (`api.disablekey=false`)
  - Wired `ZAP_API_KEY` through environment/config

