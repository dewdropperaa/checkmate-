"""Authenticated-scan configuration helpers (safe for ScanState / checkpoints).

Decrypts credentials only inside ``load_runtime_auth`` and returns them in a
short-lived dataclass that must never be written into LangGraph state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from core.accounts import (
    SiteAuthCredentialRecord,
    get_site,
    get_site_auth_credentials,
    get_site_auth_credentials_by_target,
    get_site_by_target,
)
from core.credential_crypto import (
    DecryptedCredentials,
    EncryptedCredentialBlob,
    decrypt_credentials,
)
from core.destructive_actions import merge_excluded_paths
from core.plans import can_use_authenticated_scanning

logger = logging.getLogger(__name__)


@dataclass
class AuthScanPublicMeta:
    """Checkpoint-safe metadata about authenticated scanning for a run."""

    configured: bool = False
    enabled: bool = False
    plan_allows: bool = False
    username_hint: str | None = None
    login_url: str | None = None
    excluded_paths: list[str] = field(default_factory=list)
    login_succeeded: bool | None = None
    fallback_reason: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_state_dict(self) -> dict[str, Any]:
        """Serialize for ScanState — never includes secrets."""
        return {
            "configured": self.configured,
            "enabled": self.enabled,
            "plan_allows": self.plan_allows,
            "username_hint": self.username_hint,
            "login_url": self.login_url,
            "excluded_paths": list(self.excluded_paths),
            "login_succeeded": self.login_succeeded,
            "fallback_reason": self.fallback_reason,
            "warnings": list(self.warnings),
        }


@dataclass
class AuthScanRuntime:
    """In-memory runtime auth bundle. Do not put on ScanState."""

    meta: AuthScanPublicMeta
    credentials: DecryptedCredentials | None = None
    username_field: str | None = None
    password_field: str | None = None
    record: SiteAuthCredentialRecord | None = None


def resolve_site_for_scan(org_id: str | None, target: str) -> str | None:
    if not org_id:
        return None
    site = get_site_by_target(org_id, target)
    return site.id if site else None


def build_public_auth_meta(
    *,
    org_id: str | None,
    site_id: str | None = None,
    target: str | None = None,
    extra_excluded: list[str] | None = None,
) -> AuthScanPublicMeta:
    """Build checkpoint-safe auth metadata without decrypting secrets."""
    meta = AuthScanPublicMeta()
    if not org_id:
        return meta

    record: SiteAuthCredentialRecord | None = None
    if site_id:
        record = get_site_auth_credentials(site_id, org_id=org_id)
    elif target:
        record = get_site_auth_credentials_by_target(org_id, target)

    if record is None:
        return meta

    plan_allows = can_use_authenticated_scanning(org_id)
    excluded = merge_excluded_paths(record.excluded_paths, extra_excluded or [])
    meta.configured = True
    meta.plan_allows = plan_allows
    meta.username_hint = record.username_hint
    meta.login_url = record.login_url
    meta.excluded_paths = excluded

    if not plan_allows:
        meta.enabled = False
        meta.fallback_reason = "plan_downgrade"
        meta.warnings.append(
            "Authenticated scanning is not included in your current plan. "
            "Scan will proceed as an unauthenticated visitor. "
            "Upgrade to Pro or Agency to re-enable authenticated scanning "
            "(stored credentials were not deleted)."
        )
        return meta

    meta.enabled = True
    return meta


def load_runtime_auth(
    *,
    org_id: str | None,
    site_id: str | None = None,
    target: str | None = None,
    extra_excluded: list[str] | None = None,
) -> AuthScanRuntime:
    """Load auth config and decrypt credentials only when the plan allows use.

    Decrypted credentials live only on the returned AuthScanRuntime object.
    """
    meta = build_public_auth_meta(
        org_id=org_id,
        site_id=site_id,
        target=target,
        extra_excluded=extra_excluded,
    )
    runtime = AuthScanRuntime(meta=meta)
    if not meta.configured or not meta.enabled or not org_id:
        return runtime

    record: SiteAuthCredentialRecord | None = None
    if site_id:
        record = get_site_auth_credentials(site_id, org_id=org_id)
    elif target:
        record = get_site_auth_credentials_by_target(org_id, target)
    if record is None:
        return runtime

    try:
        creds = decrypt_credentials(
            EncryptedCredentialBlob(
                encrypted_data_key=record.encrypted_data_key,
                ciphertext=record.encrypted_payload,
            )
        )
    except Exception:
        logger.exception("Failed to decrypt site credentials; falling back to unauthenticated")
        meta.enabled = False
        meta.fallback_reason = "decrypt_failed"
        meta.warnings.append(
            "Stored credentials could not be decrypted. "
            "Scan will proceed as an unauthenticated visitor."
        )
        return AuthScanRuntime(meta=meta)

    runtime.credentials = creds
    runtime.username_field = record.username_field
    runtime.password_field = record.password_field
    runtime.record = record
    return runtime


def redact_auth_fields_from_state(values: dict[str, Any]) -> dict[str, Any]:
    """Strip any accidental secret-bearing keys before checkpoint inspection/tests."""
    banned = {
        "password",
        "username",
        "credentials",
        "decrypted_credentials",
        "auth_password",
        "auth_username",
        "login_password",
    }
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key.lower() in banned:
            continue
        if isinstance(value, dict):
            cleaned[key] = redact_auth_fields_from_state(value)
        else:
            cleaned[key] = value
    return cleaned


def ensure_site_id(org_id: str | None, site_id: str | None, target: str) -> str | None:
    if site_id:
        site = get_site(site_id)
        if site and (org_id is None or site.org_id == org_id):
            return site.id
    return resolve_site_for_scan(org_id, target)
