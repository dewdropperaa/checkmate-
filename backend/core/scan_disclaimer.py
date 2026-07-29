"""Fixed legal/trust-positioning copy for scan coverage & limitations.

This wording is a reviewed product asset. Do not paraphrase per-report or
let LLM synthesis rewrite it. Tests snapshot SCAN_COVERAGE_DISCLAIMER to
catch silent drift.
"""

from __future__ import annotations

# Canonical English disclaimer — included in every report format and the
# dashboard coverage section. Treat as immutable without an explicit product
# review.
SCAN_COVERAGE_DISCLAIMER = (
    "This is an automated vulnerability scan, not a manual penetration test. "
    "It does not test complex business logic, does not attempt social engineering, "
    "and authenticated-scan coverage is limited to the account and paths you "
    "configured. For a comprehensive security assessment, consider a manual "
    "penetration test from a qualified provider in addition to this ongoing "
    "security monitoring."
)

# Section titles used consistently across report formats.
COVERAGE_SECTION_TITLE = "What this scan covered"
COVERAGE_LIMITATIONS_HEADING = "What this scan does not cover"
