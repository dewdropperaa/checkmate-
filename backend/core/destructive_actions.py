"""Destructive-action path/form exclusion for authenticated scanning.

Belt-and-suspenders defense:
1. Path exclusions (user-configured + auto-detected during recon)
2. Keyword matching on form actions / field names so a destructive
   action reachable via an unexpected path is still blocked
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

# Paths / form actions containing these tokens are treated as destructive
# by default and auto-excluded during recon. User may un-exclude explicitly.
DEFAULT_DESTRUCTIVE_KEYWORDS: tuple[str, ...] = (
    "delete-account",
    "delete_account",
    "deleteaccount",
    "remove-account",
    "cancel-subscription",
    "cancel_subscription",
    "unsubscribe-all",
    "unsubscribe_all",
    "logout-all",
    "logout_all",
    "deactivate",
    "purge",
    "destroy",
    "wipe",
    "terminate",
    "close-account",
    "close_account",
)

# Broader token list for form action / field-name matching (second layer).
DEFAULT_DESTRUCTIVE_FORM_KEYWORDS: tuple[str, ...] = (
    "delete",
    "remove",
    "cancel",
    "deactivate",
    "unsubscribe-all",
    "unsubscribe_all",
    "purge",
    "destroy",
    "wipe",
    "terminate",
    "close-account",
    "close_account",
    "logout-all",
    "logout_all",
)


# Common Cyrillic/Greek homoglyphs folded to ASCII before keyword matching.
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0410": "a",
        "\u0415": "e",
        "\u041e": "o",
    }
)


def _normalize_match_text(value: str) -> str:
    """Unicode-normalize and URL-decode text before destructive keyword matching."""
    decoded = unquote(value or "")
    normalized = unicodedata.normalize("NFKC", decoded)
    return normalized.translate(_CONFUSABLES).lower()


def _normalize_path(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        path = parsed.path or "/"
    else:
        path = raw if raw.startswith("/") else f"/{raw}"
    # Drop trailing slash except root
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return _normalize_match_text(path)


def path_matches_exclusion(url_or_path: str, excluded_paths: Iterable[str]) -> bool:
    """True if ``url_or_path`` is covered by any excluded path prefix/exact match."""
    candidate = _normalize_path(url_or_path)
    if not candidate:
        return False
    for exclusion in excluded_paths:
        ex = _normalize_path(str(exclusion))
        if not ex:
            continue
        if candidate == ex or candidate.startswith(ex.rstrip("/") + "/"):
            return True
        # Also match when exclusion is a substring token in the path segments
        # (e.g. exclusion "/delete-account" matches "/app/delete-account/confirm")
        if ex.strip("/") and ex.strip("/") in candidate:
            return True
    return False


def contains_destructive_keyword(
    text: str,
    keywords: Iterable[str] | None = None,
) -> bool:
    """True if text contains a destructive keyword as a path/token fragment."""
    haystack = _normalize_match_text(text)
    if not haystack:
        return False
    for kw in keywords or DEFAULT_DESTRUCTIVE_KEYWORDS:
        token = _normalize_match_text(str(kw)).strip()
        if not token:
            continue
        if token in haystack:
            return True
    return False


def detect_destructive_paths(urls: Iterable[str]) -> list[str]:
    """Return normalized paths that look destructive (for default exclusion)."""
    found: list[str] = []
    seen: set[str] = set()
    for url in urls:
        path = _normalize_path(str(url))
        if not path or path in seen:
            continue
        if contains_destructive_keyword(path, DEFAULT_DESTRUCTIVE_KEYWORDS):
            seen.add(path)
            found.append(path)
    return found


def filter_excluded_urls(
    urls: Iterable[str],
    excluded_paths: Iterable[str],
) -> list[str]:
    """Drop URLs whose path matches an exclusion."""
    return [
        u for u in urls if not path_matches_exclusion(str(u), excluded_paths)
    ]


def filter_excluded_endpoints(
    endpoints: Iterable[dict[str, Any]],
    excluded_paths: Iterable[str],
) -> list[dict[str, Any]]:
    """Drop endpoint dicts whose url/path matches an exclusion."""
    kept: list[dict[str, Any]] = []
    for ep in endpoints:
        url = str(ep.get("url") or ep.get("path") or "")
        if path_matches_exclusion(url, excluded_paths):
            continue
        kept.append(ep)
    return kept


def is_destructive_form(
    *,
    action: str | None = None,
    field_names: Iterable[str] | None = None,
    keywords: Iterable[str] | None = None,
) -> bool:
    """Second-layer guard: block forms whose action or fields look destructive."""
    kws = tuple(keywords) if keywords is not None else DEFAULT_DESTRUCTIVE_FORM_KEYWORDS
    if action and contains_destructive_keyword(action, kws):
        return True
    for name in field_names or ():
        if contains_destructive_keyword(str(name), kws):
            return True
    return False


def merge_excluded_paths(
    configured: Iterable[str],
    discovered: Iterable[str],
) -> list[str]:
    """Union configured + auto-detected exclusions, preserving order."""
    merged: list[str] = []
    seen: set[str] = set()
    for item in list(configured) + list(discovered):
        path = _normalize_path(str(item))
        if path and path not in seen:
            seen.add(path)
            merged.append(path)
    return merged


def katana_exclude_regexes(excluded_paths: Iterable[str]) -> list[str]:
    """Build Katana ``-ef`` regex patterns from excluded path prefixes."""
    patterns: list[str] = []
    for path in excluded_paths:
        normalized = _normalize_path(str(path))
        if not normalized or normalized == "/":
            continue
        escaped = re.escape(normalized)
        patterns.append(escaped)
    return patterns
