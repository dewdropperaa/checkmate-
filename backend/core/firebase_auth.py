"""Firebase Admin ID-token verification for protected API routes.

Client-supplied user ids are never trusted. Every authenticated request must
present a Firebase ID token in ``Authorization: Bearer <token>``; this module
verifies the signature and claims server-side.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.config import get_settings

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)
_init_lock = threading.Lock()
_firebase_ready = False


@dataclass(frozen=True)
class AuthenticatedUser:
    """Verified Firebase identity — never taken from the client body."""

    uid: str
    email: str | None
    email_verified: bool
    name: str | None
    picture: str | None
    sign_in_provider: str | None
    claims: dict[str, Any]


def _init_firebase_admin() -> None:
    """Idempotent Admin SDK init. Credentials stay server-side only."""
    global _firebase_ready
    if _firebase_ready:
        return

    with _init_lock:
        if _firebase_ready:
            return

        import firebase_admin
        from firebase_admin import credentials

        settings = get_settings()
        options: dict[str, Any] = {}
        if settings.firebase_project_id:
            options["projectId"] = settings.firebase_project_id

        if firebase_admin._apps:  # type: ignore[attr-defined]
            _firebase_ready = True
            return

        cred = None
        if settings.firebase_credentials_json:
            # Service-account JSON string — NEVER expose as NEXT_PUBLIC_*.
            try:
                info = json.loads(settings.firebase_credentials_json)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "FIREBASE_CREDENTIALS_JSON is not valid JSON"
                ) from exc
            cred = credentials.Certificate(info)
        elif settings.firebase_credentials_path:
            cred = credentials.Certificate(settings.firebase_credentials_path)
        else:
            # Application Default Credentials (GCP / GOOGLE_APPLICATION_CREDENTIALS).
            try:
                cred = credentials.ApplicationDefault()
            except Exception:  # noqa: BLE001
                if settings.app_env == "production":
                    raise RuntimeError(
                        "Firebase Admin credentials required in production. "
                        "Set FIREBASE_CREDENTIALS_JSON or "
                        "FIREBASE_CREDENTIALS_PATH / GOOGLE_APPLICATION_CREDENTIALS."
                    )
                logger.warning(
                    "Firebase Admin credentials not configured; "
                    "ID token verification will fail until they are set."
                )
                # Still initialize with projectId so verify_id_token can fetch
                # Google public keys when ADC becomes available later.
                firebase_admin.initialize_app(options=options or None)
                _firebase_ready = True
                return

        firebase_admin.initialize_app(cred, options or None)
        _firebase_ready = True


def verify_id_token(token: str) -> AuthenticatedUser:
    """Verify a Firebase ID token and return the authenticated user.

    Raises HTTPException 401 on missing/invalid/expired tokens.
    """
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "missing_token",
                "message": "Authorization Bearer token is required.",
            },
        )

    try:
        _init_firebase_admin()
        from firebase_admin import auth as firebase_auth

        decoded = firebase_auth.verify_id_token(token.strip())
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - map all verify failures to 401
        logger.info("Firebase ID token verification failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_token",
                "message": "Invalid or expired authentication token.",
            },
        ) from exc

    uid = decoded.get("uid") or decoded.get("sub")
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_token",
                "message": "Token is missing a subject claim.",
            },
        )

    firebase_info = decoded.get("firebase") or {}
    provider = firebase_info.get("sign_in_provider")

    return AuthenticatedUser(
        uid=str(uid),
        email=decoded.get("email"),
        email_verified=bool(decoded.get("email_verified", False)),
        name=decoded.get("name"),
        picture=decoded.get("picture"),
        sign_in_provider=provider,
        claims=dict(decoded),
    )


async def require_firebase_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> AuthenticatedUser:
    """FastAPI dependency: require a valid Firebase ID token on the request."""
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "missing_token",
                "message": "Authorization Bearer token is required.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_id_token(creds.credentials)


def ensure_email_verified(user: AuthenticatedUser) -> None:
    """Reject sensitive actions until the Firebase email_verified claim is true."""
    if user.email_verified:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "email_not_verified",
            "message": (
                "Verify your email address before using this feature. "
                "Check your inbox (and spam folder) for the verification link."
            ),
        },
    )


async def require_verified_firebase_user(
    user: AuthenticatedUser = Depends(require_firebase_user),
) -> AuthenticatedUser:
    """FastAPI dependency: valid Firebase token with a verified email address."""
    ensure_email_verified(user)
    return user


def try_verify_bearer_token(token: str) -> AuthenticatedUser | None:
    """Best-effort verify for hybrid identity (Firebase JWT vs opaque API keys).

    Returns None when the token is not a verifiable Firebase ID token so callers
    can fall back to legacy API-key identity for the Chrome extension.
    """
    # Firebase ID tokens are JWTs (three base64 segments).
    if token.count(".") != 2:
        return None
    try:
        return verify_id_token(token)
    except HTTPException:
        return None
