#!/usr/bin/env python3
"""Reproduce nuclei/header-checks/testssl/retirejs against a target locally."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("REQUIRE_TOOLCHAIN_AT_STARTUP", "false")
os.environ.setdefault("AUTHORIZED_TARGETS", "example.com")

from tools.nuclei_tool import NucleiTool
from tools.header_checks import HeaderChecker
from tools.testssl_tool import TestSSLTool
from tools.retirejs_tool import RetireJSTool


async def run_one(name: str, coro):
    try:
        res = await coro
    except Exception as exc:
        print(f"=== {name} EXCEPTION {type(exc).__name__}: {str(exc)[:1000]}")
        return
    data = getattr(res, "data", res)
    success = getattr(res, "success", None)
    err = getattr(res, "error", None)
    if success is None and isinstance(data, dict):
        success = data.get("success")
    if err is None and isinstance(data, dict):
        err = data.get("error")
    print(f"=== {name} success={success}")
    print(f"error={str(err)[:1000]}")
    if isinstance(data, dict):
        for k in ("stderr", "message", "skip_reason", "exit_code"):
            if data.get(k) not in (None, ""):
                print(f"{k}={str(data.get(k))[:1000]}")
        findings = data.get("findings")
        if isinstance(findings, list):
            print(f"findings_count={len(findings)}")


async def main() -> None:
    target = os.environ.get("QA_SMOKE_TARGET", "https://example.com")
    print("target=", target)
    scope: dict = {}
    await run_one("nuclei", NucleiTool().run(target, scope))
    await run_one("header-checks", HeaderChecker().run(target, scope))
    await run_one("testssl", TestSSLTool().run(target, scope))
    await run_one("retirejs", RetireJSTool().run(target, scope))


if __name__ == "__main__":
    asyncio.run(main())
