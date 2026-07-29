"""Envelope encryption for site scan credentials at rest.

A master key (from ``CREDENTIALS_MASTER_KEY`` env) encrypts a per-record
data key; that data key encrypts the username/password payload. Decrypted
values must never be written to the database, logs, reports, or LangGraph
checkpoint state — call sites decrypt only in local variables at use time.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_ENV_KEY = "CREDENTIALS_MASTER_KEY"


class CredentialCryptoError(Exception):
    """Raised when encryption/decryption cannot proceed safely."""


@dataclass(frozen=True)
class EncryptedCredentialBlob:
    """Opaque ciphertext stored in the database (never plaintext)."""

    encrypted_data_key: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class DecryptedCredentials:
    """In-memory only — never serialize into ScanState or checkpoints."""

    username: str
    password: str


def _load_master_fernet() -> Fernet:
    raw = os.environ.get(_ENV_KEY, "").strip()
    if not raw:
        try:
            from core.config import get_settings

            settings_key = getattr(get_settings(), "credentials_master_key", None)
            if settings_key:
                raw = str(settings_key).strip()
        except Exception:
            raw = ""
    if not raw:
        raise CredentialCryptoError(
            f"{_ENV_KEY} must be set to a Fernet key. Generate one with: "
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )
    try:
        key = raw.encode("ascii") if isinstance(raw, str) else raw
        return Fernet(key)
    except (ValueError, TypeError, Exception) as exc:
        raise CredentialCryptoError(
            f"{_ENV_KEY} is not a valid Fernet key"
        ) from exc


def generate_master_key() -> str:
    """Return a new url-safe Fernet master key (for ops / docs)."""
    return Fernet.generate_key().decode("utf-8")


def encrypt_credentials(username: str, password: str) -> EncryptedCredentialBlob:
    """Envelope-encrypt username/password for storage."""
    if not username or not password:
        raise CredentialCryptoError("username and password are required")

    master = _load_master_fernet()
    data_key = Fernet.generate_key()
    data_fernet = Fernet(data_key)
    payload = json.dumps(
        {"username": username, "password": password},
        separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = data_fernet.encrypt(payload)
    encrypted_data_key = master.encrypt(data_key)
    return EncryptedCredentialBlob(
        encrypted_data_key=encrypted_data_key,
        ciphertext=ciphertext,
    )


def decrypt_credentials(blob: EncryptedCredentialBlob) -> DecryptedCredentials:
    """Decrypt a stored blob. Caller must keep the result ephemeral."""
    master = _load_master_fernet()
    try:
        data_key = master.decrypt(blob.encrypted_data_key)
        data_fernet = Fernet(data_key)
        raw = data_fernet.decrypt(blob.ciphertext)
    except InvalidToken as exc:
        raise CredentialCryptoError("failed to decrypt credentials") from exc

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialCryptoError("credential payload corrupt") from exc

    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise CredentialCryptoError("credential payload missing fields")
    return DecryptedCredentials(username=username, password=password)


def redact_username(username: str) -> str:
    """Produce a display hint that is safe for UI / reports / approval gates."""
    value = (username or "").strip()
    if not value:
        return "(unknown)"
    if "@" in value:
        local, _, domain = value.partition("@")
        if len(local) <= 1:
            return f"*@{domain}"
        return f"{local[0]}***@{domain}"
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}***{value[-1]}"


def assert_no_plaintext_leak(text: str, *secrets_to_check: str) -> None:
    """Test helper: raise if any secret substring appears in ``text``."""
    lowered = text.lower()
    for secret in secrets_to_check:
        if secret and secret.lower() in lowered:
            raise AssertionError("plaintext credential leaked into output")


def random_token(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)
