"""
Prism - Local Pre-Commit Code Review System

A multi-agent code review pipeline that runs on the developer's machine
before code is pushed to GitHub. Each agent checks a specific concern.
"""

import os
from pathlib import Path

__version__ = "2.0.1"

_ENV_LOADED = False


def _parse_env_file(path):
    """Parse a .env file using only the standard library.

    ``python-dotenv`` is an optional extra, so a plain ``pip install`` must not
    depend on it: without this fallback a .env written by ``prism key set`` is
    ignored and the AI agents report "no API key configured" with no clue why.
    """
    values = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return values

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values


def load_env():
    """Load the nearest .env file into os.environ (idempotent).

    Runs at package import so every entry point (CLI, LSP, library use) sees
    the same provider keys. Previously only `prism.cli` loaded .env, so
    `prism.lsp` or a direct `review_with_agent` call silently ran without a
    key and reported "no API key configured".
    """
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True

    here = Path(__file__).resolve().parent
    # Project-local .env wins over the tool's own config, so a developer can
    # point PRISM at a different key without editing the install.
    candidates = (
        Path.cwd() / ".env",
        Path.cwd() / ".config" / ".env",
        here.parent / ".env",
        here / ".env",
        here.parent / ".config" / ".env",
        here / ".config" / ".env",
        here.parent.parent / ".env",
    )
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            from dotenv import load_dotenv
        except ImportError:
            # Mirror python-dotenv's default: existing environment wins.
            for key, value in _parse_env_file(candidate).items():
                os.environ.setdefault(key, value)
        else:
            load_dotenv(candidate)
        return


load_env()