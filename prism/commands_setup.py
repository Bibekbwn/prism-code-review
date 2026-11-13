"""Setup, key and agent commands.

Extracted from cli_commands.py; behaviour unchanged.
"""

import json
import shutil
import sys
from pathlib import Path

import prism
from prism.agents import AGENT_REGISTRY
from prism.cli_config import DEFAULT_AGENTS, CONFIDENCE_THRESHOLD, load_config
from prism.commands_common import _agent_table, _save_config, _set_agent_enabled
from prism.ignore import (
    DEFAULT_IGNORE, IGNORE_FILE, add_patterns, is_ignored, read_ignore_file,
    remove_patterns, reset_patterns,
)


def _cmd_ignore(args):
    """Manage which files PRISM skips during pre-commit review.

    The exclusion list lives in .prismignore (one gitignore-style pattern per
    line) so a developer can keep docs, assets and generated files out of the
    review without touching the rest of the PRISM config.
    """
    action = getattr(args, "action", None) or "list"

    if action == "list":
        patterns = read_ignore_file()
        print("Ignore file: {}".format(IGNORE_FILE))
        if not patterns:
            print("  (empty - only the built-in defaults apply)")
        for pattern in patterns:
            print("  {}".format(pattern))
        print("")
        print("Built-in defaults:")
        for pattern in DEFAULT_IGNORE:
            print("  {} (default)".format(pattern))
        print("")
        print("Staged files PRISM would review:")
        try:
            from prism.cli_config import get_staged_files
            raw = get_staged_files(apply_ignore=False)
        except Exception as exc:
            print("  (could not read staged files: {})".format(exc))
            raw = []
        if not raw:
            print("  (nothing staged)")
        for f in raw:
            state = "SKIP" if is_ignored(f) else "review"
            print("  [{}] {}".format(state, f))
        return

    if action == "add":
        targets = list(getattr(args, "patterns", None) or [])
        if not targets:
            print("Usage: prism ignore add <pattern> [pattern...]")
            sys.exit(1)
        added = add_patterns(targets)
        if added:
            print("Added to {}: {}".format(IGNORE_FILE, ", ".join(added)))
        else:
            print("Nothing added (already ignored or a built-in default).")
        return

    if action == "remove":
        targets = list(getattr(args, "patterns", None) or [])
        if not targets:
            print("Usage: prism ignore remove <pattern> [pattern...]")
            sys.exit(1)
        removed = remove_patterns(targets)
        if removed:
            print("Removed from {}: {}".format(IGNORE_FILE, ", ".join(removed)))
        else:
            print("None of those patterns were in {}.".format(IGNORE_FILE))
            print("Built-in defaults cannot be removed here; use "
                  "`prism ignore reset` to clear custom entries.")
        return

    if action == "reset":
        reset_patterns()
        print("Restored the default ignore list.")
        return

    print("Unknown ignore action: {}".format(action))
    sys.exit(1)


def _cmd_mode(args):
    """Show or switch the agent selection mode.

    ``all`` runs regex + AI agents, ``regex`` runs only the deterministic
    agents (no API calls), and ``none`` skips agents entirely while still
    writing an empty report so reports/dashboard/JSON keep working.
    """
    from prism.modes import VALID_MODES, describe, get_mode, set_mode

    config = load_config()
    wanted = getattr(args, "mode", None)

    if not wanted:
        current = get_mode(config)
        print("Mode: {} - {}".format(current, describe(current)))
        print("")
        print("Available modes:")
        for mode in VALID_MODES:
            marker = "*" if mode == current else " "
            print("  {} {:<6} {}".format(marker, mode, describe(mode)))
        print("")
        print("Usage: prism mode <all|regex|none>")
        return

    wanted = wanted.lower()
    if wanted not in VALID_MODES:
        print("Unknown mode: {}".format(wanted))
        print("Valid modes: {}".format(", ".join(VALID_MODES)))
        sys.exit(1)

    stored = set_mode(wanted, config)
    print("Mode set to {} - {}".format(stored, describe(stored)))
    if wanted == "regex":
        print("No API calls will be made; AI agents are disabled.")
    elif wanted == "none":
        print("No agents run. Reports are still written so the dashboard and")
        print("JSON output keep working.")
    else:
        print("Regex agents and AI agents both run (needs an API key).")


def _cmd_key(args):
    """Manage API keys for AI providers.

    Only one provider key is kept at a time: setting a key for one provider
    removes the keys of the other providers so exactly one is active.
    """
    env_path = Path(".env")
    if not env_path.exists():
        env_path = Path(".config/.env")

    valid_providers = ["gemini", "openai", "claude"]
    env_vars = {
        "gemini": "GEMINI_API_KEY",
        "openai": "OPENAI_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
    }
    all_key_vars = set(env_vars.values())

    if args.action == "set":
        provider = args.provider
        key = args.key

        if provider not in valid_providers:
            print("Invalid provider: {}".format(provider))
            print("Valid providers: {}".format(", ".join(valid_providers)))
            return

        if not key:
            print("No key provided. Usage: prism key set --provider gemini --key YOUR_KEY")
            return

        # A placeholder written to .env makes `key status` report "No API keys
        # configured" right after a successful `key set`, which looks like a bug.
        if _is_placeholder_value(key):
            print("That looks like a placeholder, not a real key.")
            print("Usage: prism key set --provider gemini --key YOUR_REAL_KEY")
            sys.exit(1)

        env_var = env_vars[provider]

        if env_path.exists():
            lines = env_path.read_text().splitlines()
        else:
            lines = []
            env_path.parent.mkdir(parents=True, exist_ok=True)

        key_written = False
        provider_written = False
        new_lines = []
        for line in lines:
            stripped = line.strip()
            # Drop keys belonging to OTHER providers (mutual exclusivity)
            if any(stripped.startswith(v + "=") for v in all_key_vars):
                if stripped.startswith(env_var + "="):
                    new_lines.append('{env_var}="{key}"'.format(env_var=env_var, key=key))
                    key_written = True
                # else: silently drop the other provider's key
                continue
            if stripped.startswith("MODEL_PROVIDER="):
                new_lines.append("MODEL_PROVIDER={}".format(provider))
                provider_written = True
                continue
            new_lines.append(line)

        if not key_written:
            new_lines.append('{env_var}="{key}"'.format(env_var=env_var, key=key))
        if not provider_written:
            new_lines.append("MODEL_PROVIDER={}".format(provider))

        env_path.write_text("\n".join(new_lines) + "\n")
        print("Set {provider} API key in {path}".format(provider=provider, path=env_path))
        print("Environment variable: {}".format(env_var))
        print("Active provider: {}".format(provider))
        print("Other provider keys were removed (only one key is kept).")

    elif args.action == "delete":
        if not env_path.exists():
            print("No .env file found at {}".format(env_path.as_posix()))
            return

        lines = env_path.read_text().splitlines()
        new_lines = []
        deleted = []
        for line in lines:
            stripped = line.strip()
            removed = None
            for provider, env_var in env_vars.items():
                if stripped.startswith(env_var + "="):
                    removed = env_var
                    break
            if removed:
                deleted.append(removed)
            else:
                new_lines.append(line)

        if deleted:
            env_path.write_text("\n".join(new_lines) + "\n")
            print("Deleted API key(s) from {}: {}".format(
                env_path.as_posix(), ", ".join(deleted)))
        else:
            print("No API keys found in {}".format(env_path.as_posix()))

    elif args.action == "status":
        if not env_path.exists():
            print("No .env file found at {}".format(env_path.as_posix()))
            print("Run: prism key set --provider gemini --key YOUR_KEY")
            return

        lines = env_path.read_text().splitlines()
        found = False
        for line in lines:
            stripped = line.strip()
            for provider in valid_providers:
                env_var = env_vars[provider]
                if stripped.startswith(env_var + "="):
                    value = stripped.split("=", 1)[1].strip().strip('"')
                    if value and not _is_placeholder_value(value):
                        masked = value[:4] + "..." + value[-4:] if len(value) > 8 else "***"
                        print("{}: {}".format(provider, masked))
                        found = True
        if not found:
            print("No API keys configured in {}".format(env_path.as_posix()))
            print("Run: prism key set --provider gemini --key YOUR_KEY")
        else:
            print("\nActive provider: {}".format(_get_active_provider(lines)))


def _is_placeholder_value(value):
    """Return True if the value is a placeholder, not a real key."""
    lowered = value.lower()
    return any(marker in lowered for marker in (
        "your-", "example", "placeholder", "changeme", "xxx",
        "api-key-here", "token-here", "secret-here",
    ))


def _get_active_provider(lines):
    """Get the active provider from .env lines."""
    for line in lines:
        if line.strip().startswith("MODEL_PROVIDER="):
            return line.split("=", 1)[1].strip()
    return "gemini (default)"


def _cmd_init(args):
    """Scaffold config and env WITHOUT overwriting existing files.

    prism.json ships with the repo, so this never clobbers a custom config.
    .env is created from .env.example if missing; the developer then runs
    `prism key set` — no manual file editing required.
    """
    if Path("prism.json").exists() or Path(".prism.json").exists():
        print("prism.json already exists - left untouched")
    else:
        config = {
            "agents": DEFAULT_AGENTS,
            "block_on": ["critical", "high"],
            "quality_gates": {
                "max_complexity": 10,
                "max_file_length": 500,
                "min_coverage": 0,
            },
            "confidence_threshold": CONFIDENCE_THRESHOLD,
            "mode": "all",
        }
        with open("prism.json", "w") as f:
            json.dump(config, f, indent=2)
        print("Created prism.json")

    # Scaffold .env from .env.example if missing (developer never edits it)
    env = Path(".env")
    if not env.exists() and Path(".env.example").exists():
        shutil.copy(".env.example", ".env")
        print("Created .env from .env.example")
    elif not env.exists():
        print("No .env.example found")

    # .prismignore is optional (the defaults already cover docs/assets), but
    # creating it makes the exclusion mechanism discoverable.
    if not Path(IGNORE_FILE).exists():
        Path(IGNORE_FILE).write_text(
            "# Files PRISM skips during pre-commit review.\n"
            "# One pattern per line; '!' re-includes a path. "
            "See `prism help ignore`.\n\n",
            encoding="utf-8",
        )
        print("Created {}".format(IGNORE_FILE))

    print("Next: prism key set --provider gemini --key YOUR_API_KEY")


def _cmd_install_hook(args):
    """Install the PRISM pre-commit hook into .git/hooks/pre-commit."""
    if not Path(".git").exists():
        print("Not a git repository (no .git directory). Run this from the repo root.")
        sys.exit(1)

    hook_dir = Path(".git/hooks")
    hook_dir.mkdir(parents=True, exist_ok=True)
    hook = hook_dir / "pre-commit"

    script = Path(__file__).resolve().parent / "pre-commit-hook.sh"
    if script.exists():
        hook.write_text(script.read_text(encoding="utf-8", errors="ignore"))
    else:
        hook.write_text(
            "#!/bin/sh\n# PRISM Pre-Commit Hook\n"
            "python -m prism.cli check-staged --prompt\n"
        )
    hook.chmod(0o755)

    if not hook.stat().st_mode & 0o111:
        print("Installed pre-commit hook (note: not executable on this platform)")
    else:
        print("Installed pre-commit hook at {}".format(hook))
    print("Reviewing staged files now happens automatically on `git commit`.")


def _cmd_uninstall_hook(args):
    hook_path = Path(".git/hooks/pre-commit")
    if hook_path.exists():
        hook_path.unlink()
        print("Uninstalled pre-commit hook")
    else:
        print("No pre-commit hook found")


def _cmd_version(args):
    print("PRISM v{}".format(prism.__version__))
    print("  Architecture: skeleton + import graph + verification + tiered chunking")
    print("  Agents: 6 AI + 4 regex = 10 total")
    print("  Providers: gemini (default), claude, openai")


def _cmd_help(args):
    print("""
PRISM - Pre-Commit Code Review System
=====================================

USAGE:
    prism <command> [options]

CORE REVIEW COMMANDS:
    prism check <file>              Review a single file with all agents
    prism check <file> --json       Output results as JSON
    prism check <file> --prompt     Ask about medium/low findings interactively
    prism check <file> --fix        Apply auto-fixable changes
    prism check-staged              Review all staged git files (pre-commit hook)
    prism check-diff --base origin/main   Review the PR diff against a base branch

REPORT COMMANDS:
    prism reports                   Show review history summary
    prism report <id>               Show a specific report by ID
    prism delete-report <id>        Delete a specific report
    prism clear-reports             Delete ALL reports (asks for confirmation)
    prism dashboard                 Open visual HTML dashboard in browser

AGENT COMMANDS:
    prism agents                   List all available agents
    prism agents --enable <name>   Enable a specific agent
    prism agents --disable <name>  Disable a specific agent

SETUP COMMANDS:
    prism init                      Create prism.json config
    prism install-hook              Install pre-commit git hook
    prism key set --provider gemini --key YOUR_KEY   Set API key
    prism key status                Show current API key status
    prism key delete                Delete API keys from .env

OTHER COMMANDS:
    prism policy                    Show deviation policy
    prism feedback                  Show feedback loop stats
    prism suppressed                Show historically suppressed rules
    prism mode                      Show the current agent mode
    prism mode regex                Regex agents only (no API calls)
    prism mode none                 No agents at all (reports only)
    prism mode all                  Regex + AI agents (default)
    prism agents --enable <agent>   Re-enable a disabled agent
    prism agents --disable <agent>  Switch off a single agent (e.g. 'ai_quality')
    prism ignore                    List files skipped by pre-commit review
    prism ignore add <pattern>      Skip a file/folder (e.g. 'docs/', '*.png')
    prism ignore remove <pattern>   Stop skipping a pattern
    prism ignore reset              Restore the default ignore list
    prism help                      Show this help message

AGENT MODES:
    all     Regex agents + AI agents (default; needs an API key)
    regex   Deterministic regex agents only, no API calls
    none    No agents run; reports are still written so the dashboard,
            `prism reports` and --json output keep working

FREEZING A SINGLE AGENT:
    Use ``prism agents --disable <agent>`` to switch off exactly one regex or
    AI agent and leave the rest running - for example to silence a noisy rule
    without disabling the whole review. Names come from ``prism agents``.
    ``prism agents --enable <agent>`` turns it back on. The state lives in
    prism.json under "agents".

IGNORED FILES:
    PRISM skips documentation, assets, lock files and editor noise by default.
    The list lives in .prismignore (one pattern per line, '!pattern' to
    re-include). Use `prism ignore list` to see what would be skipped.

AI AGENTS (6 total):
    ai_security     Security review (secrets, injection, auth flaws)
    ai_quality      Code quality (complexity, duplication, maintainability)
    ai_policy       Policy compliance (docs, banned patterns, logging)
    ai_test         Test coverage (edge cases, weak tests, coverage gaps)
    ai_architecture Architecture (coupling, modularity, design patterns)
    ai_performance  Performance (N+1 queries, memory, inefficient algorithms)

EXAMPLES:
    prism check app.py
    prism check app.py --json
    prism check-staged
    prism delete-report 20261108T164053Z
    prism clear-reports --force
    prism agents
    prism dashboard
""")


def _cmd_agents(args):
    """List agents and their on/off state; toggle with --enable/--disable."""
    config = load_config()
    table = _agent_table(config.get("agents", DEFAULT_AGENTS))

    enable = getattr(args, "enable", None)
    disable = getattr(args, "disable", None)

    if enable:
        agents_cfg = config.get("agents", DEFAULT_AGENTS)
        if _set_agent_enabled(agents_cfg, enable, True):
            config["agents"] = agents_cfg
            _save_config(config)
            table = _agent_table(agents_cfg)
            print("Enabled agent: {}".format(enable))
        else:
            print("Agent already enabled: {}".format(enable))

    if disable:
        agents_cfg = config.get("agents", DEFAULT_AGENTS)
        if disable not in _agent_table(agents_cfg):
            print("Agent not found: {}".format(disable))
            return
        if _set_agent_enabled(agents_cfg, disable, False):
            config["agents"] = agents_cfg
            _save_config(config)
            table = _agent_table(agents_cfg)
            print("Disabled agent: {}".format(disable))
        else:
            print("Agent already disabled: {}".format(disable))

    print("")
    print("Agents (prism.json \"agents\"):")
    enabled = {name for name, on in table.items() if on}
    names = list(AGENT_REGISTRY.keys())
    for extra in table:
        if extra not in names:
            names.append(extra)
    for name in names:
        state = "enabled" if name in enabled else "disabled"
        desc = AGENT_REGISTRY[name].description if name in AGENT_REGISTRY else ""
        print("  [{:8}] {}{}".format(
            state, name, ": " + desc if desc else ""))
    print("")
    print("Toggle one: prism agents --enable <agent> | --disable <agent>")
