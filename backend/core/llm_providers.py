"""Ordered multi-provider LLM client for ai_synthesis.

Free-tier-first strategy by default (Gemini → Groq). Providers are selected from
`settings.ai_llm_provider_list`; each call tries providers in order and falls
through on timeout, 429, 5xx, or model-not-found. Uses httpx so tests can mock
without installing vendor SDKs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from core.config import Settings, get_settings

logger = logging.getLogger(__name__)

# Temperature for grounded security synthesis — keep near-deterministic.
DEFAULT_TEMPERATURE = 0.1


@dataclass(frozen=True)
class LLMResponse:
    text: str
    provider: str
    model: str


@dataclass(frozen=True)
class LLMCallResult:
    """Outcome of a multi-provider attempt."""

    response: LLMResponse | None
    provider_used: str  # concrete provider id, or "none"
    error: str | None = None


class LLMProviderError(Exception):
    """Raised for a single-provider failure that should trigger fallback."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


def _provider_api_key(settings: Settings, provider: str) -> str | None:
    mapping = {
        "gemini": settings.gemini_api_key,
        "groq": settings.groq_api_key,
        "openai": settings.openai_api_key,
        "anthropic": settings.anthropic_api_key,
    }
    key = mapping.get(provider)
    if key is None:
        return None
    key = str(key).strip()
    return key or None


def _provider_model(settings: Settings, provider: str) -> str:
    mapping = {
        "gemini": settings.gemini_model,
        "groq": settings.groq_model,
        "openai": settings.openai_model,
        "anthropic": settings.anthropic_model,
    }
    return mapping.get(provider, "")


def configured_providers(settings: Settings | None = None) -> list[str]:
    """Return ordered providers that have an API key configured."""
    settings = settings or get_settings()
    ready: list[str] = []
    for provider in settings.ai_llm_provider_list:
        if _provider_api_key(settings, provider):
            ready.append(provider)
    return ready


def any_llm_configured(settings: Settings | None = None) -> bool:
    return bool(configured_providers(settings))


def _raise_for_http_status(response: httpx.Response, provider: str) -> None:
    status = response.status_code
    body = (response.text or "")[:500]
    if status == 429:
        raise LLMProviderError(f"{provider} rate-limited (429): {body}")
    if status == 404 or (
        status == 400
        and any(
            token in body.lower()
            for token in ("model_not_found", "not found", "does not exist", "invalid model")
        )
    ):
        raise LLMProviderError(f"{provider} model unavailable ({status}): {body}")
    if status >= 500:
        raise LLMProviderError(f"{provider} unavailable ({status}): {body}")
    if status >= 400:
        raise LLMProviderError(f"{provider} client error ({status}): {body}", retryable=False)


def _call_gemini(
    prompt: str,
    *,
    api_key: str,
    model: str,
    timeout: float,
    temperature: float,
    client: httpx.Client | None = None,
) -> LLMResponse:
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent"
    )
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature},
    }
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(url, params={"key": api_key}, json=payload)
        _raise_for_http_status(response, "gemini")
        data = response.json()
        candidates = data.get("candidates") or []
        if not candidates:
            raise LLMProviderError("gemini returned no candidates")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(str(p.get("text", "")) for p in parts).strip()
        if not text:
            raise LLMProviderError("gemini returned empty text")
        return LLMResponse(text=text, provider="gemini", model=model)
    except httpx.TimeoutException as exc:
        raise LLMProviderError(f"gemini timeout after {timeout}s") from exc
    except httpx.HTTPError as exc:
        raise LLMProviderError(f"gemini transport error: {exc}") from exc
    finally:
        if owns_client:
            http.close()


def _call_openai_compatible(
    prompt: str,
    *,
    provider: str,
    api_key: str,
    model: str,
    base_url: str,
    timeout: float,
    temperature: float,
    client: httpx.Client | None = None,
) -> LLMResponse:
    url = f"{base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(url, headers=headers, json=payload)
        _raise_for_http_status(response, provider)
        data = response.json()
        choices = data.get("choices") or []
        if not choices:
            raise LLMProviderError(f"{provider} returned no choices")
        message = choices[0].get("message") or {}
        text = str(message.get("content") or "").strip()
        if not text:
            raise LLMProviderError(f"{provider} returned empty text")
        return LLMResponse(text=text, provider=provider, model=model)
    except httpx.TimeoutException as exc:
        raise LLMProviderError(f"{provider} timeout after {timeout}s") from exc
    except httpx.HTTPError as exc:
        raise LLMProviderError(f"{provider} transport error: {exc}") from exc
    finally:
        if owns_client:
            http.close()


def _call_anthropic(
    prompt: str,
    *,
    api_key: str,
    model: str,
    timeout: float,
    temperature: float,
    client: httpx.Client | None = None,
) -> LLMResponse:
    url = "https://api.anthropic.com/v1/messages"
    payload = {
        "model": model,
        "max_tokens": 2048,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(url, headers=headers, json=payload)
        _raise_for_http_status(response, "anthropic")
        data = response.json()
        blocks = data.get("content") or []
        text = "".join(
            str(b.get("text", "")) for b in blocks if b.get("type") == "text"
        ).strip()
        if not text:
            raise LLMProviderError("anthropic returned empty text")
        return LLMResponse(text=text, provider="anthropic", model=model)
    except httpx.TimeoutException as exc:
        raise LLMProviderError(f"anthropic timeout after {timeout}s") from exc
    except httpx.HTTPError as exc:
        raise LLMProviderError(f"anthropic transport error: {exc}") from exc
    finally:
        if owns_client:
            http.close()


_OPENAI_COMPAT_BASE: dict[str, str] = {
    "groq": "https://api.groq.com/openai/v1",
    "openai": "https://api.openai.com/v1",
}


def call_provider(
    provider: str,
    prompt: str,
    *,
    settings: Settings | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    client: httpx.Client | None = None,
) -> LLMResponse:
    """Call a single named provider. Raises LLMProviderError on failure."""
    settings = settings or get_settings()
    api_key = _provider_api_key(settings, provider)
    if not api_key:
        raise LLMProviderError(f"{provider} has no API key configured", retryable=False)
    model = _provider_model(settings, provider)
    timeout = float(settings.ai_synthesis_timeout_seconds)

    if provider == "gemini":
        return _call_gemini(
            prompt,
            api_key=api_key,
            model=model,
            timeout=timeout,
            temperature=temperature,
            client=client,
        )
    if provider in _OPENAI_COMPAT_BASE:
        return _call_openai_compatible(
            prompt,
            provider=provider,
            api_key=api_key,
            model=model,
            base_url=_OPENAI_COMPAT_BASE[provider],
            timeout=timeout,
            temperature=temperature,
            client=client,
        )
    if provider == "anthropic":
        return _call_anthropic(
            prompt,
            api_key=api_key,
            model=model,
            timeout=timeout,
            temperature=temperature,
            client=client,
        )
    raise LLMProviderError(f"unknown provider '{provider}'", retryable=False)


def call_with_fallback(
    prompt: str,
    *,
    settings: Settings | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    client: httpx.Client | None = None,
    call_fn: Callable[..., LLMResponse] | None = None,
    scan_id: str | None = None,
    org_id: str | None = None,
) -> LLMCallResult:
    """Try configured providers in order; return first success or provider_used=none."""
    settings = settings or get_settings()
    providers = configured_providers(settings)
    if not providers:
        return LLMCallResult(response=None, provider_used="none", error="no_api_key")

    correlation = {
        key: value
        for key, value in (("scan_id", scan_id), ("org_id", org_id))
        if value
    }

    invoker = call_fn or call_provider
    last_error: str | None = None
    for provider in providers:
        try:
            response = invoker(
                provider,
                prompt,
                settings=settings,
                temperature=temperature,
                client=client,
            )
            logger.info(
                "ai_llm_provider_served",
                extra={
                    "event": "ai_llm_provider_served",
                    "provider": provider,
                    "model": response.model,
                    **correlation,
                },
            )
            return LLMCallResult(response=response, provider_used=provider, error=None)
        except LLMProviderError as exc:
            last_error = str(exc)
            logger.warning(
                "ai_llm_provider_failed",
                extra={
                    "event": "ai_llm_provider_failed",
                    "provider": provider,
                    "error": last_error,
                    "retryable": exc.retryable,
                    **correlation,
                },
            )
            if not exc.retryable:
                # Non-retryable on primary still allows trying the next provider
                # (e.g. unknown model on one vendor shouldn't block another).
                continue
            continue
        except Exception as exc:  # noqa: BLE001 — never let LLM blow up the scan
            last_error = f"unexpected {provider} error: {exc}"
            logger.exception(
                "ai_llm_provider_unexpected",
                extra={
                    "event": "ai_llm_provider_unexpected",
                    "provider": provider,
                    **correlation,
                },
            )
            continue

    return LLMCallResult(
        response=None,
        provider_used="none",
        error=last_error or "all_providers_failed",
    )


def describe_provider_role(provider_used: str, settings: Settings | None = None) -> str:
    """Classify which slot served the call: primary / fallback / none."""
    if not provider_used or provider_used == "none":
        return "none"
    settings = settings or get_settings()
    ordered = configured_providers(settings)
    if not ordered:
        return "none"
    if provider_used == ordered[0]:
        return "primary"
    if provider_used in ordered:
        return "fallback"
    return "none"


def provider_coverage_fields(
    provider_used: str,
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    return {
        "provider": provider_used,
        "provider_role": describe_provider_role(provider_used, settings),
        "providers_configured": configured_providers(settings),
    }
