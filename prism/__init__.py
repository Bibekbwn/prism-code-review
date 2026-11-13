"""
Prism - Local Pre-Commit Code Review System

A multi-agent code review pipeline that runs on the developer's machine
before code is pushed to GitHub. Each agent checks a specific concern.
"""

from pathlib import Path

__version__ = "2.0.0"

_ENV_LOADED = False


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

    try:
        from dotenv import load_dotenv
    except ImportError:
        return

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
        if candidate.exists():
            load_dotenv(candidate)
            return


load_env()