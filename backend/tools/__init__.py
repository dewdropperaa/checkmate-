"""Security tool wrappers."""

from tools.base import (
    BaseSecurityTool,
    BinaryValidationError,
    ScopeViolationError,
    ToolExecutionError,
    ToolResult,
    ToolTimeoutError,
    parse_json_output,
    resolve_binary_path,
    run_subprocess_safely,
    validate_scope,
)
from tools.firecrawl_tool import FirecrawlTool
from tools.httpx_tool import HttpxLangChainTool, HttpxTool
from tools.katana_tool import KatanaLangChainTool, KatanaTool
from tools.subfinder_tool import SubfinderLangChainTool, SubfinderTool

from tools.schemas import Finding, Severity, deduplicate_findings
from tools.nuclei_tool import NucleiTool
from tools.testssl_tool import TestSSLTool
from tools.retirejs_tool import RetireJSTool
from tools.header_checks import HeaderChecker
from tools.zap_tool import ZAPTool
from tools.sqlmap_tool import SQLMapTool, find_injectable_urls

__all__ = [
    "BaseSecurityTool",
    "BinaryValidationError",
    "FirecrawlTool",
    "HttpxLangChainTool",
    "HttpxTool",
    "KatanaLangChainTool",
    "KatanaTool",
    "ScopeViolationError",
    "SubfinderLangChainTool",
    "SubfinderTool",
    "ToolExecutionError",
    "ToolResult",
    "ToolTimeoutError",
    "parse_json_output",
    "resolve_binary_path",
    "run_subprocess_safely",
    "validate_scope",
    # Detection tools
    "Finding",
    "Severity",
    "deduplicate_findings",
    "NucleiTool",
    "TestSSLTool",
    "RetireJSTool",
    "HeaderChecker",
    "ZAPTool",
    "SQLMapTool",
    "find_injectable_urls",
]
