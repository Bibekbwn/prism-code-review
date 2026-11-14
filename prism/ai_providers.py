"""LLM provider initialization and API call dispatch.

Supports gemini, claude, and openai. Provider is selected via the
MODEL_PROVIDER env var (default: gemini). Each provider returns a
(client, provider_name, call_fn) tuple; call_fn is bound to the right
API shape so pipeline code never branches on provider.
"""

import os
import json
import re
import time
import random
import logging
import importlib
import concurrent.futures

from prism import token_usage

def _int_env(name, default):
    """Read an int env var, falling back to the default when unset or not a number.

    A typo in a tuning variable must not take the whole CLI down at import time.
    """
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return int(default)


# Per-attempt wall-clock cap. A provider that accepts the socket but never
# answers (or an HTTP client that ignores its timeout) must not stall the CLI
# for minutes: every attempt is abandoned after this many seconds.
API_TIMEOUT = _int_env("PRISM_API_TIMEOUT", 30)
MAX_RETRIES = _int_env("PRISM_MAX_RETRIES", 2)

# How much file content is sent to the model in one call. Truncation is a cost
# control, not a correctness limit: the skeleton and the import graph carry the
# structure, so a large file still gets reviewed.
MAX_CONTENT_CHARS = _int_env("PRISM_MAX_CONTENT_CHARS", 16000)

# Retry pacing: exponential backoff with jitter, capped by a total budget so a
# bad provider cannot stall the CLI. Defaults keep a single flaky call well
# under a second of sleeping while still absorbing transient 504s.
RETRY_BASE_DELAY = float(os.getenv("PRISM_RETRY_BASE_DELAY", "0.2"))
RETRY_MAX_DELAY = float(os.getenv("PRISM_RETRY_MAX_DELAY", "1.0"))
RETRY_BUDGET = float(os.getenv("PRISM_RETRY_BUDGET", "5"))

# Simple circuit breaker: after repeated failures, fail fast for a cooldown
# instead of making every agent wait through the full retry ladder.
CIRCUIT_THRESHOLD = _int_env("PRISM_CIRCUIT_THRESHOLD", 5)
CIRCUIT_COOLDOWN = float(os.getenv("PRISM_CIRCUIT_COOLDOWN", "60"))

_logger = logging.getLogger(__name__)
_no_key_warned = False
_circuit_failures = 0
_circuit_open_until = 0.0

# Provider catalogue. `kind` selects the client shape; `key`/`model` are the
# env vars that hold the API key and model override. `base_url` (+ optional
# `base_url_default`) targets an OpenAI-compatible endpoint, which is how the
# free tiers (OpenRouter, Groq) and paid alternatives (Together, DeepSeek,
# Mistral) are supported without new client code.
PROVIDERS = {
    "gemini": {
        "kind": "gemini", "key": "GEMINI_API_KEY",
        "model": "GEMINI_MODEL", "default_model": "gemini-3.5-flash-lite",
    },
    "claude": {
        "kind": "claude", "key": "ANTHROPIC_API_KEY",
        "model": "CLAUDE_MODEL", "default_model": "claude-3-5-sonnet-20241022",
    },
    "openai": {
        "kind": "openai", "key": "OPENAI_API_KEY",
        "model": "OPENAI_MODEL", "default_model": "gpt-4o",
        "base_url": "OPENAI_BASE_URL",
    },
    "openrouter": {
        "kind": "openai", "key": "OPENROUTER_API_KEY",
        "model": "OPENROUTER_MODEL", "default_model": "openai/gpt-4o-mini",
        "base_url": "OPENROUTER_BASE_URL",
        "base_url_default": "https://openrouter.ai/api/v1",
    },
    "groq": {
        "kind": "openai", "key": "GROQ_API_KEY",
        "model": "GROQ_MODEL", "default_model": "llama-3.3-70b-versatile",
        "base_url": "GROQ_BASE_URL",
        "base_url_default": "https://api.groq.com/openai/v1",
    },
    "together": {
        "kind": "openai", "key": "TOGETHER_API_KEY",
        "model": "TOGETHER_MODEL",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "base_url": "TOGETHER_BASE_URL",
        "base_url_default": "https://api.together.xyz/v1",
    },
    "deepseek": {
        "kind": "openai", "key": "DEEPSEEK_API_KEY",
        "model": "DEEPSEEK_MODEL", "default_model": "deepseek-chat",
        "base_url": "DEEPSEEK_BASE_URL",
        "base_url_default": "https://api.deepseek.com",
    },
    "mistral": {
        "kind": "openai", "key": "MISTRAL_API_KEY",
        "model": "MISTRAL_MODEL", "default_model": "mistral-large-latest",
        "base_url": "MISTRAL_BASE_URL",
        "base_url_default": "https://api.mistral.ai/v1",
    },
}

PROVIDER_ALIASES = {
    "anthropic": "claude", "google": "gemini",
    "gpt": "openai", "open-ai": "openai",
}

# Which provider/model the current call belongs to, for token accounting.
_ACTIVE_MODEL = {"provider": "gemini", "model": "gemini-3.5-flash-lite"}


def _warn_no_key(provider, env_var):
    """Print a one-time, actionable message when no API key is configured.

    Returning None silently made every AI agent return [] with no indication
    why — a developer would assume their code is clean. This makes the
    failure loud instead.
    """
    global _no_key_warned
    if _no_key_warned:
        return
    _no_key_warned = True
    _logger.warning(
        "No API key for %s. AI agents are disabled. "
        "Run `prism init` to scaffold .env, then add %s=your_key. "
        "Deterministic regex agents still run with --effort lite.",
        provider, env_var,
    )


def _is_placeholder_key(key):
    """Reject obviously fake keys so tests and misconfigured installs fail fast."""
    if not key:
        return True
    lowered = key.lower()
    return any(marker in lowered for marker in (
        "your-", "example", "placeholder", "changeme", "xxx",
        "api-key-here", "token-here", "secret-here",
    ))


def _resolve_provider(provider):
    """Normalize a provider name (aliases included) or read MODEL_PROVIDER."""
    provider = (provider or os.getenv("MODEL_PROVIDER", "gemini")).lower()
    return PROVIDER_ALIASES.get(provider, provider)


def _record_usage(input_tokens, output_tokens, prompt_text, response_text):
    """Record one call's tokens, estimating when the provider gave none."""
    provider = _ACTIVE_MODEL["provider"]
    model = _ACTIVE_MODEL["model"]
    if input_tokens or output_tokens:
        token_usage.record(provider, model, input_tokens, output_tokens)
    else:
        token_usage.record(
            provider, model,
            token_usage.estimate_tokens(prompt_text),
            token_usage.estimate_tokens(response_text),
            estimated=True,
        )


def get_model(provider=None, model_name=None):
    """Lazy-load an LLM client. Returns (client, provider, call_fn) or (None, None, None)."""
    provider = _resolve_provider(provider)
    spec = PROVIDERS.get(provider)
    if spec is None:
        _logger.error("Unknown MODEL_PROVIDER: %s", provider)
        return None, None, None

    model_name = model_name or os.getenv(spec["model"]) or spec["default_model"]
    api_key = os.getenv(spec["key"])
    if not api_key or _is_placeholder_key(api_key):
        _warn_no_key(provider, spec["key"])
        return None, None, None

    _ACTIVE_MODEL["provider"] = provider
    _ACTIVE_MODEL["model"] = model_name
    kind = spec["kind"]

    if kind == "gemini":
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            return genai.GenerativeModel(model_name), provider, _call_fn
        except Exception as exc:
            _logger.error("Failed to initialize Gemini: %s", exc)
            return None, None, None

    if kind == "claude":
        try:
            anthropic = __import__("anthropic")
            return anthropic.Anthropic(api_key=api_key), provider, _call_claude
        except Exception as exc:
            _logger.error("Failed to initialize Claude: %s", exc)
            return None, None, None

    # openai / OpenAI-compatible
    try:
        openai = importlib.import_module("openai")
        kwargs = {"api_key": api_key}
        base_url = (os.getenv(spec.get("base_url", ""))
                    or spec.get("base_url_default"))
        if base_url:
            kwargs["base_url"] = base_url
        return openai.OpenAI(**kwargs), provider, _call_openai
    except Exception as exc:
        _logger.error("Failed to initialize %s: %s", provider, exc)
        return None, None, None


def _build_prompt(system_prompt, file_path, content, skeleton="", cross_file_context=""):
    """Assemble the user prompt from system + context + skeleton + content."""
    parts = []
    if cross_file_context:
        parts.append(cross_file_context)
    if skeleton:
        parts.append("\n## Structural Skeleton (table of contents for this file)\n" + skeleton)
    parts.append("\n## File: {}\n".format(file_path))
    parts.append("\n## Content\n{}".format(content[:MAX_CONTENT_CHARS]))
    return system_prompt + "\n" + "\n".join(parts)


def _call_fn(model, system_prompt, file_path, content, agent_name,
             skeleton="", timeout=None, cross_file_context=""):
    """Call Gemini API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    prompt = _build_prompt(system_prompt, file_path, content, skeleton, cross_file_context)

    def _do_generate(prompt_text, _timeout=timeout):
        # Ask for JSON at the API level: it removes the markdown fences and
        # prose preambles that used to make chunked reviews fail parsing.
        response = model.generate_content(
            prompt_text,
            generation_config={"response_mime_type": "application/json"},
            request_options={"timeout": _timeout},
        )
        text = response.text or "{}"
        usage = getattr(response, "usage_metadata", None)
        _record_usage(
            getattr(usage, "prompt_token_count", 0),
            getattr(usage, "candidates_token_count", 0),
            prompt_text, text,
        )
        return text

    return _call_with_retry(_do_generate, prompt, agent_name, timeout)


def _call_claude(model, system_prompt, file_path, content, agent_name,
                 skeleton="", timeout=None, cross_file_context=""):
    """Call Claude API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    user_prompt = _build_prompt("", file_path, content, skeleton, cross_file_context)

    def _do_call():
        response = model.messages.create(
            model=_ACTIVE_MODEL["model"],
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = response.content[0].text
        usage = getattr(response, "usage", None)
        _record_usage(
            getattr(usage, "input_tokens", 0),
            getattr(usage, "output_tokens", 0),
            user_prompt, text,
        )
        return text

    return _call_with_retry(_do_call, None, agent_name, timeout)


def _call_openai(model, system_prompt, file_path, content, agent_name,
                 skeleton="", timeout=None, cross_file_context=""):
    """Call OpenAI API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    user_prompt = _build_prompt("", file_path, content, skeleton, cross_file_context)

    def _do_call():
        response = model.chat.completions.create(
            model=_ACTIVE_MODEL["model"],
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        text = response.choices[0].message.content
        usage = getattr(response, "usage", None)
        _record_usage(
            getattr(usage, "prompt_tokens", 0),
            getattr(usage, "completion_tokens", 0),
            user_prompt, text,
        )
        return text

    return _call_with_retry(_do_call, None, agent_name, timeout)


def _parse_json_response(text):
    """Extract a JSON object from a model response.

    Models sometimes wrap JSON in prose or markdown fences, or emit trailing
    commas. Return the parsed dict, or None if no valid object is present.
    """
    if not text:
        return None
    cleaned = str(text).replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, TypeError):
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end <= start:
        return None
    candidate = cleaned[start:end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        return None


def _circuit_open():
    return time.monotonic() < _circuit_open_until


def _record_failure():
    global _circuit_failures, _circuit_open_until
    _circuit_failures += 1
    if _circuit_failures >= CIRCUIT_THRESHOLD:
        _circuit_open_until = time.monotonic() + CIRCUIT_COOLDOWN
        _logger.error(
            "Provider circuit opened after %d consecutive failures; "
            "pausing AI calls for %ds", _circuit_failures, int(CIRCUIT_COOLDOWN)
        )


def _record_success():
    global _circuit_failures, _circuit_open_until
    _circuit_failures = 0
    _circuit_open_until = 0.0


def _retry_delay(attempt, deadline):
    """Backoff with jitter, never sleeping past the total retry budget."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 0.0
    delay = min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * (2 ** attempt))
    delay = min(delay, remaining)
    jitter_cap = min(0.1, max(0.0, remaining - delay))
    return delay + random.uniform(0, jitter_cap)


def _invoke_with_deadline(call_fn, prompt, timeout):
    """Run a provider call in a worker thread and abandon it after `timeout`.

    The provider SDK's own timeout is not always honoured (a hung TCP
    connection can block past it), and the retry ladder cannot help while the
    first call is still running. Bounding the wall clock here keeps every
    agent's worst case at `(MAX_RETRIES + 1) * timeout`.
    """
    if prompt is not None:
        def _run():
            return call_fn(prompt)
    else:
        def _run():
            return call_fn()

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_run)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        _logger.error("provider call exceeded %.0fs; abandoning attempt", timeout)
        raise TimeoutError("provider call exceeded {:.0f}s".format(timeout))
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:  # Python < 3.9 has no cancel_futures
            executor.shutdown(wait=False)


def _call_with_retry(call_fn, prompt, agent_name, timeout):
    """Shared retry + JSON parse logic for all providers.

    Retries on transport errors *and* malformed JSON, with capped backoff and
    a circuit breaker. Always returns a dict; failures carry `_failed`.
    """
    deadline = time.monotonic() + RETRY_BUDGET
    last_error = "unknown error"
    error_kind = "transport"
    attempts = 0

    for attempt in range(MAX_RETRIES + 1):
        attempts += 1
        if _circuit_open():
            _logger.error("%s skipped: provider circuit is open", agent_name)
            return {"findings": [], "summary": "Provider temporarily unavailable",
                    "_failed": True, "_error": "provider circuit is open",
                    "_error_kind": "circuit_open"}

        attempt_timeout = max(1.0, timeout or API_TIMEOUT)
        try:
            text = _invoke_with_deadline(call_fn, prompt, attempt_timeout)
            data = _parse_json_response(text)
            if data is not None:
                _record_success()
                return data
            last_error = "model did not return valid JSON"
            error_kind = "invalid_json"
        except Exception as exc:
            last_error = str(exc)
            error_kind = "transport"

        if attempt >= MAX_RETRIES:
            break

        delay = _retry_delay(attempt, deadline)
        if delay <= 0:
            _logger.warning("%s retry budget exhausted after %s", agent_name, last_error)
            break
        _logger.warning(
            "%s attempt %d/%d failed: %s. Retrying in %.1fs...",
            agent_name, attempt + 1, MAX_RETRIES + 1, last_error, delay
        )
        time.sleep(delay)

    _record_failure()
    message = "API error after {} attempt(s): {}".format(attempts, last_error)
    return {"findings": [], "summary": message, "_failed": True, "_error": message,
            "_error_kind": error_kind}