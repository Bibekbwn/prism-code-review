"""Token accounting for AI provider calls.

Providers report usage differently (Gemini ``usage_metadata``, OpenAI
``usage``, Anthropic ``usage``). This module normalizes them into a
process-wide ledger, and estimates tokens when a provider does not report
them so the CLI can always show a number.

Call ``reset()`` at the start of a review, ``record()`` from each provider
call, and ``summary()``/``format_summary()`` to report.
"""

import logging
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_usage = []  # list of dicts: provider, model, input_tokens, output_tokens, estimated

# Average characters per token across common BPE tokenizers. Only used when a
# provider does not return an exact count.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text):
    """Cheap token estimate for text (used only as a fallback)."""
    if not text:
        return 0
    return max(1, len(text) // _CHARS_PER_TOKEN)


def record(provider, model, input_tokens, output_tokens, estimated=False):
    """Append one provider call to the ledger (thread-safe)."""
    with _lock:
        _usage.append({
            "provider": provider,
            "model": model,
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "estimated": bool(estimated),
        })


def reset():
    """Clear the ledger (call once per review)."""
    with _lock:
        _usage.clear()


def snapshot():
    """Return a copy of the raw per-call records."""
    with _lock:
        return list(_usage)


def summary():
    """Aggregate the ledger into a reportable dict."""
    with _lock:
        calls = len(_usage)
        input_tokens = sum(u["input_tokens"] for u in _usage)
        output_tokens = sum(u["output_tokens"] for u in _usage)
        estimated = sum(1 for u in _usage if u["estimated"])
        by_provider = {}
        for u in _usage:
            entry = by_provider.setdefault(u["provider"], {
                "calls": 0, "input_tokens": 0, "output_tokens": 0,
            })
            entry["calls"] += 1
            entry["input_tokens"] += u["input_tokens"]
            entry["output_tokens"] += u["output_tokens"]
    return {
        "calls": calls,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "estimated_calls": estimated,
        "by_provider": by_provider,
    }


def format_summary():
    """Human-readable one-liner for CLI output."""
    s = summary()
    if not s["calls"]:
        return "Token usage: 0 tokens (no AI calls)"
    return (
        "Token usage: {total:,} total "
        "(in {inp:,} / out {out:,}), {calls} call(s){est}".format(
            total=s["total_tokens"], inp=s["input_tokens"],
            out=s["output_tokens"], calls=s["calls"],
            est=" (estimated)" if s["estimated_calls"] else "",
        )
    )