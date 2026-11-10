"""PRISM CLI entry point.

This module is a thin facade. The implementation is split across:
  - cli_config.py  : config, git helpers, deviation policy
  - cli_review.py  : review orchestration, report formatting, JSON output
  - cli_commands.py: argparse setup + command dispatch + self-tests

Importing this module runs the @register_agent decorators for the
deterministic regex agents so they are available alongside the AI agents.
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

# Add parent directory to path so prism imports work when run as executable
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load .env file if it exists (for GEMINI_API_KEY and other settings)
try:
    from dotenv import load_dotenv
    for env_path in [
        Path(__file__).parent.parent.parent / ".env",
        Path(__file__).parent.parent / ".env",
        Path(__file__).parent.parent / ".config" / ".env",
        Path.cwd() / ".env",
        Path.cwd() / ".config" / ".env",
    ]:
        if env_path.exists():
            load_dotenv(env_path)
            break
except ImportError:
    pass

# Importing these modules runs their @register_agent decorators so the
# deterministic regex agents are available alongside the AI agents.
from prism import agents_security, agents_quality, agents_policy, agents_test
from prism.logging_config import logger

from prism.cli_config import (
    DEFAULT_AGENTS, CONFIDENCE_THRESHOLD, load_config, load_deviation_policy,
    get_staged_files, run_changed_tests, get_file_diff, is_deviation,
)
from prism.cli_review import review_file, format_report, json_output
from prism.cli_commands import (
    _run_self_tests, _run_benchmark, _cmd_agents, _cmd_help, _cmd_version,
    _cmd_uninstall_hook, _cmd_stats, _cmd_config, _cmd_init, _cmd_install_hook,
    _cmd_policy, _cmd_feedback, _cmd_suppressed, _cmd_reports, _cmd_dashboard,
    _cmd_report, _cmd_delete_report, _cmd_clear_reports, _cmd_cache,
    _cmd_check, _cmd_check_staged,
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
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="Review a file")
    check.add_argument("file", help="File to review")
    check.add_argument("--fix", action="store_true", help="Apply auto-fixable changes")
    check.add_argument("--json", action="store_true", help="Output results as JSON")
    check.add_argument("--prompt", action="store_true",
                       help="Ask developer about medium/low findings")
    check.add_argument("--effort", choices=["lite", "balanced", "max"],
                       default="balanced", help="AI review effort level")
    check.add_argument("--fast", action="store_true",
                       help="Use two-pass summarization for large files")

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

    sub.add_parser("init", help="Create prism.json config")
    sub.add_parser("install-hook", help="Install pre-commit hook")
    sub.add_parser("policy", help="Show deviation policy")
    sub.add_parser("feedback", help="Show feedback loop stats")
    sub.add_parser("suppressed", help="Show historically suppressed rules")
    sub.add_parser("reports", help="Show review history")
    sub.add_parser("report", help="Show a specific report by ID").add_argument("id")
    sub.add_parser("dashboard", help="Open visual report dashboard in browser")

    delete_cmd = sub.add_parser("delete-report", help="Delete a specific report")
    delete_cmd.add_argument("id", help="Report ID to delete")
    clear_cmd = sub.add_parser("clear-reports", help="Delete ALL reports")
    clear_cmd.add_argument("--force", action="store_true", help="Skip confirmation")

    agents_cmd = sub.add_parser("agents", help="List available agents")
    agents_cmd.add_argument("--enable", help="Enable a specific agent")
    agents_cmd.add_argument("--disable", help="Disable a specific agent")

    sub.add_parser("help", help="Show all commands and their uses")
    sub.add_parser("version", help="Show PRISM version")
    sub.add_parser("uninstall-hook", help="Remove pre-commit hook")
    sub.add_parser("stats", help="Show review statistics")

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
    "test": _run_self_tests,
    "benchmark": _run_benchmark,
}


# Backwards-compatible re-exports for code that imports from prism.cli
from prism.cli_commands import (
    _json_output_staged as _json_output_staged,
    _review_one as _review_one,
)
_json_output = json_output

def main():
    parser = build_parser()
    args = parser.parse_args()

    handler = _COMMANDS.get(args.command)
    if handler is None:
        parser.print_help()
        return
    handler(args)


if __name__ == "__main__":
    main()
