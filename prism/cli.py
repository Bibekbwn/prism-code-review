"""PRISM CLI entry point.

This module is a thin facade: it builds the argparse parser and dispatches to
the command handlers. The implementation is split across:
  - cli_config.py      : config, git helpers, deviation policy
  - cli_review.py      : review orchestration, report formatting, JSON output
  - cli_commands.py    : check / check-staged / check-diff, self-tests
  - commands_common.py : helpers shared by the command handlers
  - commands_reports.py: reports, cache, config, stats, dashboard
  - commands_setup.py  : key, init, hook, version, help, agents

Importing this module runs the @register_agent decorators for the
deterministic regex agents so they are available alongside the AI agents.
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path so prism imports work when run as executable
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load .env file if it exists (for GEMINI_API_KEY and other settings).
# prism/__init__.py already does this at package import; the call is kept
# explicit (and idempotent) so this module works even if imported oddly.
from prism import load_env as _load_env
_load_env()

# Importing these modules runs their @register_agent decorators so the
# deterministic regex agents are available alongside the AI agents.
from prism import agents_policy, agents_quality, agents_security, agents_test

_registered_agents = (agents_policy, agents_quality, agents_security,
                      agents_test)

from prism.cli_commands import (
    _run_self_tests, _run_benchmark, _cmd_check, _cmd_check_staged,
    _cmd_check_diff, _cmd_scan,
)
from prism.ai_providers import PROVIDERS as _PROVIDERS
from prism.commands_reports import (
    _cmd_reports, _cmd_report, _cmd_delete_report, _cmd_clear_reports,
    _cmd_dashboard, _cmd_stats, _cmd_config, _cmd_policy, _cmd_feedback,
    _cmd_suppressed, _cmd_cache,
)
from prism.commands_setup import (
    _cmd_key, _cmd_init, _cmd_install_hook, _cmd_uninstall_hook, _cmd_version,
    _cmd_help, _cmd_agents, _cmd_ignore, _cmd_mode, _cmd_doctor,
)


def build_parser():
    """Build the argparse parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="prism", description="PRISM - Pre-Commit Code Review"
    )
    parser.add_argument(
        "--effort", choices=["lite", "balanced", "max"],
        default="balanced", help="AI review effort level",
    )
    parser.add_argument(
        "--version", action="store_true",
        help="Show the PRISM version and exit (same as `prism version`)",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="Review a file")
    check.add_argument("file", help="File to review")
    check.add_argument("--fix", action="store_true", help="Apply auto-fixable changes")
    check.add_argument("--yes", action="store_true",
                       help="Apply --fix changes without the confirmation prompt")
    check.add_argument("--json", action="store_true", help="Output results as JSON")
    check.add_argument("--prompt", action="store_true",
                       help="Ask developer about medium/low findings")
    check.add_argument("--effort", choices=["lite", "balanced", "max"],
                       default="balanced", help="AI review effort level")
    check.add_argument("--fast", action="store_true",
                       help="Use two-pass summarization for large files")
    check.add_argument("--no-dashboard", action="store_true",
                       help="Do not open the HTML dashboard after review")

    check_staged = sub.add_parser("check-staged", help="Review staged git changes")
    check_staged.add_argument("--json", action="store_true", help="Output results as JSON")
    check_staged.add_argument("--prompt", action="store_true",
                              help="Ask developer about medium/low findings")
    check_staged.add_argument("--effort", choices=["lite", "balanced", "max"],
                              default="balanced", help="AI review effort level")
    check_staged.add_argument("--fast", action="store_true",
                              help="Use two-pass summarization for large files")
    check_staged.add_argument("--dashboard", action="store_true",
                              help="Open visual dashboard after review")
    check_staged.add_argument("--test", action="store_true",
                              help="Run pytest on changed Python files before review")
    check_staged.add_argument("--no-dashboard", action="store_true",
                              help="Do not open the HTML dashboard after review")

    check_diff = sub.add_parser(
        "check-diff", aliases=["diff"],
        help="Review the diff against a base branch (PR review)")
    check_diff.add_argument("--base", default="origin/main",
                            help="Base ref to diff against (default: origin/main)")
    check_diff.add_argument("--json", action="store_true", help="Output results as JSON")
    check_diff.add_argument("--effort", choices=["lite", "balanced", "max"],
                            default="balanced", help="AI review effort level")
    check_diff.add_argument("--fast", action="store_true",
                            help="Use two-pass summarization for large files")
    check_diff.add_argument("--no-dashboard", action="store_true",
                            help="Do not open the HTML dashboard after review")

    sub.add_parser("init", help="Create prism.json config")
    sub.add_parser("install-hook", help="Install pre-commit hook")
    sub.add_parser("policy", help="Show deviation policy")
    sub.add_parser("feedback", help="Show feedback loop stats")
    sub.add_parser("suppressed", help="Show historically suppressed rules")
    sub.add_parser("reports", help="Show review history")
    sub.add_parser("report", help="Show a specific report by ID").add_argument("id")
    sub.add_parser("dashboard", help="Open visual report dashboard in browser")
    sub.add_parser("doctor", help="Check environment and provider setup")

    scan_cmd = sub.add_parser(
        "scan",
        help="Review every file under a path (whole-project audit)")
    scan_cmd.add_argument("path", nargs="?", default=".",
                          help="Root directory to scan (default: .)")
    scan_cmd.add_argument("--json", action="store_true",
                          help="Output results as JSON")
    scan_cmd.add_argument("--effort", choices=["lite", "balanced", "max"],
                          default="balanced", help="AI review effort level")
    scan_cmd.add_argument("--fast", action="store_true",
                          help="Use two-pass summarization for large files")
    scan_cmd.add_argument("--no-dashboard", action="store_true",
                          help="Do not open the HTML dashboard after review")

    delete_cmd = sub.add_parser("delete-report", help="Delete a specific report")
    delete_cmd.add_argument("id", help="Report ID to delete")
    clear_cmd = sub.add_parser("clear-reports", help="Delete ALL reports")
    clear_cmd.add_argument("--force", action="store_true", help="Skip confirmation")

    agents_cmd = sub.add_parser("agents", help="List available agents")
    agents_cmd.add_argument("--enable", nargs="+", metavar="NAME",
                            help="Enable one or more agents")
    agents_cmd.add_argument("--disable", nargs="+", metavar="NAME",
                            help="Disable one or more agents")

    sub.add_parser("help", help="Show all commands and their uses")
    sub.add_parser("version", help="Show PRISM version")
    sub.add_parser("uninstall-hook", help="Remove pre-commit hook")
    sub.add_parser("stats", help="Show review statistics")

    ignore_cmd = sub.add_parser(
        "ignore",
        help="Manage files skipped by pre-commit review (.prismignore)")
    ignore_cmd.add_argument("action",
                            choices=["list", "add", "remove", "reset"],
                            nargs="?", default="list",
                            help="What to do (default: list)")
    ignore_cmd.add_argument("patterns", nargs="*",
                            help="Pattern(s) to add or remove")

    mode_cmd = sub.add_parser(
        "mode",
        help="Show or switch the agent mode (all / regex / none)")
    mode_cmd.add_argument("mode", nargs="?",
                          choices=["all", "regex", "none"],
                          help="Mode to switch to (omit to show the current one)")

    config_cmd = sub.add_parser("config", help="Show or manage configuration")
    config_cmd.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"),
                            help="Set a config value")
    config_cmd.add_argument("--get", metavar="KEY", help="Get a config value")

    test_cmd = sub.add_parser("test", help="Run self-tests")
    test_cmd.add_argument("--quick", action="store_true",
                          help="Run only quick tests (skip API calls)")

    benchmark_cmd = sub.add_parser("benchmark", help="Benchmark agent performance")
    benchmark_cmd.add_argument("--file", help="File to benchmark against")
    benchmark_cmd.add_argument("--iterations", type=int, default=3,
                               help="Number of iterations")

    cache_cmd = sub.add_parser("cache", help="Manage the codebase cache")
    cache_cmd.add_argument("action", choices=["stats", "clear", "status"],
                           help="Cache action to perform")

    key_cmd = sub.add_parser("key", help="Manage API keys")
    key_cmd.add_argument("action", choices=["set", "delete", "status"],
                         help="Key action to perform")
    key_cmd.add_argument("--provider", choices=list(_PROVIDERS),
                         default=None,
                         help="AI provider (default: gemini for set)")
    key_cmd.add_argument("--key", help="API key value (required for set)")
    key_cmd.add_argument("--global", dest="global_", action="store_true",
                         help="Write the key to the install folder's .env "
                              "(tool-wide, visible from every project) "
                              "instead of the current project")

    return parser


_COMMANDS = {
    "agents": _cmd_agents,
    "help": _cmd_help,
    "version": _cmd_version,
    "uninstall-hook": _cmd_uninstall_hook,
    "stats": _cmd_stats,
    "config": _cmd_config,
    "init": _cmd_init,
    "install-hook": _cmd_install_hook,
    "policy": _cmd_policy,
    "feedback": _cmd_feedback,
    "suppressed": _cmd_suppressed,
    "reports": _cmd_reports,
    "dashboard": _cmd_dashboard,
    "report": _cmd_report,
    "delete-report": _cmd_delete_report,
    "clear-reports": _cmd_clear_reports,
    "cache": _cmd_cache,
    "check": _cmd_check,
    "check-staged": _cmd_check_staged,
    "check-diff": _cmd_check_diff,
    "diff": _cmd_check_diff,  # documented alias for check-diff
    "scan": _cmd_scan,
    "doctor": _cmd_doctor,
    "test": _run_self_tests,
    "benchmark": _run_benchmark,
    "key": _cmd_key,
    "ignore": _cmd_ignore,
    "mode": _cmd_mode,
}


def main():
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "version", False):
        _cmd_version(args)
        return

    handler = _COMMANDS.get(args.command)
    if handler is None:
        parser.print_help()
        return
    handler(args)


if __name__ == "__main__":
    main()
