"""Agent selection: mode (all/regex/none).

``mode`` is the single per-project switch, stored in ``prism.json``:

``all``   - regex agents + AI agents (default).
``regex`` - deterministic regex agents only, no API calls. Same effect as
  ``--effort lite`` but sticky, so the whole team or CI job can pin it.
``none``  - no agents at all. Nothing is reviewed; the command still writes
  an empty report so the dashboard, reports history and JSON output keep
  working (a skipped review must not look like a crash).

Switching a single agent off is ``prism agents --disable <name>``; there is
no separate per-agent freeze mechanism.
"""

import json
from pathlib import Path

MODE_ALL = "all"
MODE_REGEX = "regex"
MODE_NONE = "none"

VALID_MODES = (MODE_ALL, MODE_REGEX, MODE_NONE)

MODE_DESCRIPTIONS = {
    MODE_ALL: "Regex agents + AI agents (default)",
    MODE_REGEX: "Regex agents only, no API calls",
    MODE_NONE: "No agents - reports only, nothing is reviewed",
}


def _config_path():
    """Path of the config file that would be written."""
    for name in ("prism.json", ".prism.json"):
        if Path(name).exists():
            return Path(name)
    return Path("prism.json")


def _load_or_default(config):
    if config is not None:
        return config
    from prism.cli_config import load_config
    return load_config()


def _write_config(config):
    path = _config_path()
    with open(path, "w") as f:
        json.dump(config, f, indent=2)


def get_mode(config=None):
    """Return the effective mode from the config (``all`` when unset)."""
    config = _load_or_default(config)
    mode = (config or {}).get("mode", MODE_ALL)
    if not isinstance(mode, str) or mode.lower() not in VALID_MODES:
        return MODE_ALL
    return mode.lower()


def set_mode(mode, config=None):
    """Persist ``mode`` in prism.json. Returns the mode actually stored."""
    mode = (mode or "").lower()
    if mode not in VALID_MODES:
        return None
    config = dict(_load_or_default(config))
    config["mode"] = mode
    _write_config(config)
    return mode


def select_agents(agents, mode, effort=None):
    """Filter ``agents`` according to ``mode`` and ``effort``.

    ``--effort lite`` is a per-invocation override: it forces regex-only even
    when the stored mode is ``all``. ``mode=none`` empties the list, and a
    ``none`` mode is not silently widened by a ``max`` effort.
    """
    agents = list(agents or [])

    if mode == MODE_NONE:
        return []
    if mode == MODE_REGEX:
        agents = [a for a in agents if not a.startswith("ai_")]
    elif effort == "lite":
        # mode == all but the caller asked for the offline path
        agents = [a for a in agents if not a.startswith("ai_")]
    return agents


def describe(mode):
    """Human-readable one-liner for the CLI."""
    return MODE_DESCRIPTIONS.get(mode, MODE_DESCRIPTIONS[MODE_ALL])