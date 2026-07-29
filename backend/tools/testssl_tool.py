"""testssl.sh TLS/SSL configuration scanner wrapper.

testssl.sh checks for SSL/TLS misconfigurations including:
- Weak cipher suites
- Protocol vulnerabilities (POODLE, BEAST, etc.)
- Certificate issues
- HSTS misconfigurations

Security considerations:
- Passive scanner - only connects to verify TLS configuration
- Scope re-validated before each run
- Uses JSON output for reliable parsing
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from core.scope import is_target_authorized
from tools.base import (
    BaseSecurityTool,
    ScopeViolationError,
    ToolResult,
    run_subprocess_safely,
    validate_scope,
)
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

TESTSSL_SEVERITY_MAP = {
    "OK": None,
    "INFO": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "WARN": Severity.LOW,
    "NOT ok": Severity.MEDIUM,
    "VULNERABLE": Severity.HIGH,
}

TESTSSL_CWE_MAP = {
    "POODLE": 310,
    "BEAST": 310,
    "CRIME": 310,
    "BREACH": 310,
    "SWEET32": 310,
    "LUCKY13": 310,
    "FREAK": 310,
    "LOGJAM": 310,
    "DROWN": 310,
    "ROBOT": 310,
    "HEARTBLEED": 119,
    "CCS": 310,
    "ticketbleed": 200,
    "secure_renego": 310,
    "secure_client_renego": 310,
    "HSTS": 16,
    "HPKP": 295,
    "cert_chain": 295,
    "cert_trust": 295,
    "cert_dates": 298,
    "cert_revocation": 299,
    "cipher_order": 326,
    "cipherlist_weak": 326,
    "cipherlist_null": 326,
    "cipherlist_anon": 326,
    "cipherlist_export": 326,
    "cipherlist_des": 326,
    "cipherlist_3des": 326,
    "cipherlist_rc4": 326,
    "protocol_negotiated": 310,
    "SSLv2": 310,
    "SSLv3": 310,
    "TLS1": 310,
    "TLS1_1": 310,
}


class TestSSLInput(BaseModel):
    """Input schema for testssl.sh tool with validation."""

    target: str = Field(
        ...,
        description="Target host:port to scan (e.g., 'example.com:443')",
    )
    checks: list[str] | None = Field(
        default=None,
        description="Specific checks to run (e.g., ['--protocols', '--ciphers'])",
    )

    @field_validator("target")
    @classmethod
    def validate_target_in_scope(cls, v: str) -> str:
        """Ensure target is within the authorized scope."""
        if v.startswith(("http://", "https://")):
            parsed = urlparse(v)
            host = parsed.hostname or ""
        elif ":" in v:
            host = v.split(":")[0]
        else:
            host = v
        if not is_target_authorized(host):
            raise ValueError(
                f"Target '{v}' is not in the authorized scope. "
                "Scan aborted for safety."
            )
        return v


class TestSSLTool(BaseSecurityTool):
    """
    testssl.sh TLS/SSL configuration scanner wrapper.

    Checks for SSL/TLS vulnerabilities and misconfigurations.
    """

    name = "testssl.sh"
    description = "TLS/SSL configuration and vulnerability scanner"

    def __init__(self, timeout: float | None = None):
        super().__init__(timeout=timeout or 300.0)

    def get_binary_path(self):
        """Get testssl.sh binary path, trying both names."""
        from tools.base import resolve_binary_path, BinaryValidationError
        try:
            return resolve_binary_path("testssl.sh")
        except BinaryValidationError:
            return resolve_binary_path("testssl")

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Run testssl.sh against a target host.

        Args:
            target: Host or host:port to scan (defaults to port 443)
            scope: Scope metadata

        Returns:
            ToolResult with TLS findings
        """
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port or 443
            target = f"{host}:{port}"
        elif ":" in target:
            host = target.split(":")[0]
        else:
            host = target
            target = f"{target}:443"

        validate_scope(host)

        binary_path = self.get_binary_path()

        args = [
            "--jsonfile=-",
            "--quiet",
            "--warnings", "off",
            "--sneaky",
            target,
        ]

        logger.info(f"Running testssl.sh against {target}")

        exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
            binary_path=binary_path,
            args=args,
            timeout=self.timeout,
        )

        if timed_out:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"testssl.sh timed out after {self.timeout}s",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
            )

        findings = self._parse_findings(stdout, target)

        succeeded = exit_code == 0 or len(findings) > 0
        return ToolResult(
            tool_name=self.name,
            target=target,
            success=succeeded,
            error=(
                None
                if succeeded
                else (
                    f"testssl.sh exited with code {exit_code} and produced no findings"
                    + (f": {stderr.strip()[:300]}" if stderr.strip() else "")
                )
            ),
            data={
                "findings": [f.model_dump_for_state() for f in findings],
                "finding_count": len(findings),
                "target": target,
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
        )

    def _parse_findings(self, output: str, target: str) -> list[Finding]:
        """Parse testssl.sh JSON output into normalized Finding objects."""
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            lines = output.strip().split("\n")
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
            else:
                logger.warning("Could not parse testssl.sh JSON output")
                return findings

        scan_result = data.get("scanResult", [])
        if not scan_result:
            scan_result = [data] if "id" in data else []

        for item in scan_result if isinstance(scan_result, list) else [scan_result]:
            server_defaults = item.get("serverDefaults", [])
            protocols = item.get("protocols", [])
            vulnerabilities = item.get("vulnerabilities", [])
            ciphers = item.get("ciphers", [])
            
            all_checks = server_defaults + protocols + vulnerabilities + ciphers

            for check in all_checks:
                if not isinstance(check, dict):
                    continue

                check_id = check.get("id", "unknown")
                severity_str = check.get("severity", "INFO")
                finding_str = check.get("finding", "")

                if severity_str == "OK" or severity_str is None:
                    continue

                severity = TESTSSL_SEVERITY_MAP.get(severity_str, Severity.INFO)
                if severity is None:
                    continue

                cwe_id = None
                for key, cwe in TESTSSL_CWE_MAP.items():
                    if key.lower() in check_id.lower():
                        cwe_id = cwe
                        break

                url = f"https://{target}" if not target.startswith("http") else target

                finding = Finding(
                    tool="testssl.sh",
                    type=f"tls-{check_id}",
                    url=url,
                    severity=severity,
                    description=finding_str or f"TLS issue: {check_id}",
                    evidence=f"Check: {check_id}, Severity: {severity_str}",
                    cwe_id=cwe_id,
                    raw_data=check,
                )
                findings.append(finding)

        return findings
