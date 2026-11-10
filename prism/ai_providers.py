"""LLM provider initialization and API call dispatch.

Supports gemini, claude, and openai. Provider is selected via the
MODEL_PROVIDER env var (default: gemini). Each provider returns a
(client, provider_name, call_fn) tuple; call_fn is bound to the right
API shape so pipeline code never branches on provider.
"""

import os
import json
import time
import logging
import importlib

API_TIMEOUT = 120
MAX_RETRIES = 3
MAX_CONTENT_CHARS = 16000

_logger = logging.getLogger(__name__)
_no_key_warned = False


_logger = logging.getLogger(__name__)
_no_key_warned = False


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


def get_model(provider=None, model_name=None):
    """Lazy-load an LLM client. Returns (client, provider, call_fn) or (None, None, None)."""
    provider = (provider or os.getenv("MODEL_PROVIDER", "gemini")).lower()

    if provider == "gemini":
        model_name = model_name or os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key or _is_placeholder_key(api_key):
            _warn_no_key(provider, "GEMINI_API_KEY")
            return None, None, None
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            return genai.GenerativeModel(model_name), "gemini", _call_fn
        except Exception as exc:
            _logger.error("Failed to initialize Gemini: %s", exc)
            return None, None, None

    if provider == "claude":
        model_name = model_name or os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-20241022")
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key or _is_placeholder_key(api_key):
            _warn_no_key(provider, "ANTHROPIC_API_KEY")
            return None, None, None
        try:
            anthropic = __import__("anthropic")
            return anthropic.Anthropic(api_key=api_key), "claude", _call_claude
        except Exception as exc:
            _logger.error("Failed to initialize Claude: %s", exc)
            return None, None, None

    if provider == "openai":
        model_name = model_name or os.getenv("OPENAI_MODEL", "gpt-4o")
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key or _is_placeholder_key(api_key):
            _warn_no_key(provider, "OPENAI_API_KEY")
            return None, None, None
        try:
            openai = importlib.import_module("openai")
            return openai.OpenAI(api_key=api_key), "openai", _call_openai
        except Exception as exc:
            _logger.error("Failed to initialize OpenAI: %s", exc)
            return None, None, None

    _logger.error("Unknown MODEL_PROVIDER: %s", provider)
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
        response = model.generate_content(prompt_text, request_options={"timeout": _timeout})
        return response.text or "{}"

    return _call_with_retry(_do_generate, prompt, agent_name, timeout)


def _call_claude(model, system_prompt, file_path, content, agent_name,
                 skeleton="", timeout=None, cross_file_context=""):
    """Call Claude API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    user_prompt = _build_prompt("", file_path, content, skeleton, cross_file_context)

    def _do_call():
        response = model.messages.create(
            model=os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-20241022"),
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text

    return _call_with_retry(_do_call, None, agent_name, timeout)


def _call_openai(model, system_prompt, file_path, content, agent_name,
                 skeleton="", timeout=None, cross_file_context=""):
    """Call OpenAI API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    user_prompt = _build_prompt("", file_path, content, skeleton, cross_file_context)

    def _do_call():
        response = model.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    return _call_with_retry(_do_call, None, agent_name, timeout)


def _call_with_retry(call_fn, prompt, agent_name, timeout):
    """Shared retry + JSON parse logic for all providers."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            text = call_fn(prompt) if prompt is not None else call_fn()
            text = (text or "{}").replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except json.JSONDecodeError:
            return {"findings": [], "summary": "Parse error"}
        except Exception as exc:
            if attempt < MAX_RETRIES:
                wait = 2 ** attempt
                _logger.warning(
                    "%s attempt %d/%d failed: %s. Retrying in %ds...",
                    agent_name, attempt + 1, MAX_RETRIES + 1, exc, wait
                )
                time.sleep(wait)
            else:
                _logger.error(
                    "%s failed after %d attempts: %s",
                    agent_name, MAX_RETRIES + 1, exc
                )
    return {"findings": [], "summary": "API error after {} attempts".format(MAX_RETRIES + 1)}