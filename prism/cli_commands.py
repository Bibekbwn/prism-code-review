import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import concurrent.futures
from pathlib import Path

from prism.agents import (
    AGENT_REGISTRY, Finding, Severity, Blocker, run_pipeline,
    risk_score, quality_gates_met,
)
from prism import agents_security, agents_quality, agents_policy, agents_test
from prism.ai_common import build_skeleton
from prism.ai_security import AISecurityAgent
from prism.ai_quality import AIQualityAgent
from prism.ai_policy import AIPolicyAgent
from prism.ai_test import AITestAgent
from prism.ai_architecture import AIArchitectureAgent
from prism.ai_performance import AIPerformanceAgent
from prism.feedback import (
    load_feedback, should_suppress, suppress_summary, scan_dependencies,
)
from prism.autofix import generate_fix, apply_fixes, get_auto_fixable
from prism.logging_config import logger
from prism.reports import (
    save_report, load_report, delete_report, clear_reports, get_report_summary,
)
from prism.codebase_cache import (
    get_cached_findings, get_changed_files, cache_findings,
    get_cache_stats, clear_cache,
)

from prism.cli_config import (
    DEFAULT_AGENTS, CONFIDENCE_THRESHOLD, load_config, load_deviation_policy,
    get_staged_files, run_changed_tests, get_file_diff, is_deviation,
)
from prism.cli_review import review_file, format_report, json_output


def _run_self_tests(args):
    """Run self-tests to verify the system works correctly."""
    import pathlib

    quick = getattr(args, 'quick', False)
    print("PRISM Self-Tests")
    print("=" * 50)
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print("  [PASS] {}".format(name))
            passed += 1
        else:
            print("  [FAIL] {}".format(name))
            failed += 1

    try:
        from prism.ai_common import (
            build_skeleton, chunk_content, get_tier_for_file,
            review_with_agent, verify_findings, build_import_graph,
            get_cross_file_context, parse_findings, call_fn,
            API_TIMEOUT, MAX_CONTENT_CHARS
        )
        check("imports", True)
    except Exception as e:
        check("imports: {}".format(e), False)
        return

    sk = build_skeleton("test.py", "import os\nclass Foo:\n    def bar(self): pass")
    check("skeleton builder", "File: test.py" in sk and "Class Foo" in sk)
    check("non-python skeleton", build_skeleton("test.md", "# Hello") == "")

    content = "\n".join(["line {}".format(i) for i in range(1, 501)])
    chunks = chunk_content(content, max_lines=400, overlap=20)
    check("chunking 500 lines -> 2 chunks", len(chunks) == 2)

    check("tier 100 lines", get_tier_for_file(100)[0] == 1.0)
    check("tier 500 lines", get_tier_for_file(500)[0] == 1.5)
    check("tier 5000 lines", get_tier_for_file(5000)[0] == 2.0)
    check("tier 15000 lines", get_tier_for_file(15000)[0] == 3.0)

    from prism.agents import Finding, Severity, Blocker
    findings = [Finding(
        agent="test", severity=Severity.HIGH, category="C",
        message="test", file="test.py", line=999,
        suggestion="fix", blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id="TEST-AI-001"
    )]
    result = verify_findings(findings, "test.py", "x = 1\n")
    check("verify drops out-of-bounds", len(result) == 0)

    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp)
        (p / "a.py").write_text("import b\ndef foo(): pass\n")
        (p / "b.py").write_text("def bar(): pass\n")
        graph = build_import_graph(tmp)
        check("import graph has 2 files", len(graph) == 2)
        ctx = get_cross_file_context(str(p / "a.py"), graph, tmp)
        check("cross-file context", "imports" in ctx.lower() or "import" in ctx.lower())

    from prism.agents import AGENT_REGISTRY
    import importlib
    for mod_name in [
        "prism.ai_security", "prism.ai_quality", "prism.ai_policy",
        "prism.ai_test", "prism.ai_architecture", "prism.ai_performance",
        "prism.ai_providers", "prism.ai_findings", "prism.ai_graph",
        "prism.ai_pipeline",
        "prism.agents_security", "prism.agents_quality",
        "prism.agents_policy", "prism.agents_test",
    ]:
        importlib.import_module(mod_name)
    check("10+ agents registered", len(AGENT_REGISTRY) >= 10)

    config = load_config()
    check("config has agents", "agents" in config)

    if not quick:
        try:
            code = "x = 1\ny = 2\n"
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
                f.write(code)
                path = f.name
            sk = build_skeleton(path, code)
            results = run_pipeline(["security", "quality"], path, code, code, sk)
            check("pipeline runs", len(results) == 2)
            os.unlink(path)
        except Exception as e:
            check("pipeline: {}".format(e), False)

    print()
    print("Results: {} passed, {} failed".format(passed, failed))
    if failed > 0:
        sys.exit(1)


def _run_benchmark(args):
    """Benchmark agent performance on a file."""
    import time

    file_path = getattr(args, 'file', None)
    iterations = getattr(args, 'iterations', 3)

    if not file_path:
        print("Please specify a file: prism benchmark --file <path>")
        return

    path = Path(file_path)
    if not path.exists():
        print("File not found: {}".format(file_path))
        return

    content = path.read_text(errors="ignore")
    sk = build_skeleton(file_path, content)

    print("PRISM Benchmark: {}".format(file_path))
    print("=" * 50)
    print("File size: {} lines, {} chars".format(content.count("\n") + 1, len(content)))
    print("Iterations: {}".format(iterations))
    print()

    agents = ["security", "quality", "policy", "test"]

    for agent_name in agents:
        times = []
        for i in range(iterations):
            start = time.time()
            results = run_pipeline([agent_name], file_path, content, content, sk)
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)
            findings = len(results[0].findings) if results else 0
            print("  {} iter {}: {:.0f}ms, {} findings".format(
                agent_name, i + 1, elapsed, findings))

        avg = sum(times) / len(times)
        print("  {} average: {:.0f}ms".format(agent_name, avg))


def _cmd_agents(args):
    for name, agent in AGENT_REGISTRY.items():
        print("  {}: {}".format(name, agent.description))

    if getattr(args, "enable", None):
        config = load_config()
        if args.enable not in config.get("agents", DEFAULT_AGENTS):
            config.setdefault("agents", DEFAULT_AGENTS).append(args.enable)
            with open("prism.json", "w") as f:
                json.dump(config, f, indent=2)
            print("Enabled agent: {}".format(args.enable))
        else:
            print("Agent already enabled: {}".format(args.enable))

    if getattr(args, "disable", None):
        config = load_config()
        agents = config.get("agents", DEFAULT_AGENTS)
        if args.disable in agents:
            agents.remove(args.disable)
            config["agents"] = agents
            with open("prism.json", "w") as f:
                json.dump(config, f, indent=2)
            print("Disabled agent: {}".format(args.disable))
        else:
            print("Agent not found: {}".format(args.disable))


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
    prism help                      Show this help message

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


def _cmd_version(args):
    print("PRISM v2.0.0")
    print("  Architecture: skeleton + import graph + verification + tiered chunking")
    print("  Agents: 6 AI + 4 regex = 10 total")
    print("  Providers: gemini (default), claude, openai")


def _cmd_uninstall_hook(args):
    hook_path = Path(".git/hooks/pre-commit")
    if hook_path.exists():
        hook_path.unlink()
        print("Uninstalled pre-commit hook")
    else:
        print("No pre-commit hook found")


def _cmd_stats(args):
    print("PRISM Review Statistics")
    print("=" * 40)
    print("Use 'prism feedback' for detailed stats.")


def _cmd_config(args):
    config = load_config()
    if getattr(args, "set", None):
        key, value = args.set
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
        config[key] = value
        with open("prism.json", "w") as f:
            json.dump(config, f, indent=2)
        print("Set {} = {}".format(key, value))
    elif getattr(args, "get", None):
        print("{} = {}".format(args.get, config.get(args.get)))
    else:
        print(json.dumps(config, indent=2))


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

    print("Next: prism key set --provider gemini --key YOUR_API_KEY")


def _cmd_install_hook(args):
    hook_dir = Path(".git/hooks")
    hook_dir.mkdir(parents=True, exist_ok=True)
    hook = hook_dir / "pre-commit"
    hook.write_text(
        "#!/bin/sh\n# PRISM Pre-Commit Hook\n"
        "python -m prism.cli check-staged --prompt --json\n"
    )
    hook.chmod(0o755)
    print("Installed pre-commit hook")


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
            print("No .env file found at {}".format(env_path))
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
            print("Deleted API key(s) from {}: {}".format(env_path, ", ".join(deleted)))
        else:
            print("No API keys found in {}".format(env_path))

    elif args.action == "status":
        if not env_path.exists():
            print("No .env file found at {}".format(env_path))
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
            print("No API keys configured")
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


def _cmd_policy(args):
    policy = load_deviation_policy()
    print(json.dumps(policy, indent=2))


def _cmd_feedback(args):
    fb = load_feedback()
    print(json.dumps(fb, indent=2))


def _cmd_suppressed(args):
    print(json.dumps(suppress_summary(), indent=2))


def _cmd_reports(args):
    print(get_report_summary())


def _cmd_dashboard(args):
    """Generate a self-contained HTML dashboard with embedded report data.

    The dashboard HTML is written to .prism-reports/dashboard.html with the
    full report data (including per-finding details) inlined as JSON, so it
    renders correctly when opened via file:// (no fetch/CORS issues) and can
    be shared as a single file. The dashboard supports severity/agent filters,
    charts, and per-finding detail views.
    """
    import json as _json
    from prism.reports import load_index, load_report

    viewer = Path(__file__).parent / "dashboard.html"
    if not viewer.exists():
        print("Dashboard template not found at: {}".format(viewer))
        return

    # Load index summaries + full findings for each report
    index = load_index()
    summaries = index.get("reports", [])
    full_reports = []
    for entry in summaries:
        report = load_report(entry["id"])
        if report:
            full_reports.append(report)
        else:
            # Fall back to the index summary (no findings detail)
            full_reports.append(entry)

    template = viewer.read_text()
    embedded = _json.dumps(full_reports)

    # Inject the embedded data and call render directly (no fetch)
    injection = (
        "const EMBEDDED_REPORTS = " + embedded + ";\n"
        "loadReports();\n"
    )
    # Replace the original fetch-based loadReports with a no-op that uses embedded data
    import re
    html = template
    # Replace the loadReports function to use embedded data
    html = re.sub(
        r"function loadReports\(\) \{.*?\}\n",
        "function loadReports() {\n"
        "  render({reports: EMBEDDED_REPORTS});\n"
        "}\n",
        html,
        count=1,
        flags=re.DOTALL,
    )
    # Replace the final loadReports() call with embedded data injection
    html = html.replace(
        "loadReports();\n</script>",
        injection + "</script>"
    )

    out_path = Path(".prism-reports/dashboard.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    abs_path = str(out_path.resolve())
    print("Dashboard: file:///{}".format(abs_path.replace("\\", "/")))
    print("Reports embedded: {}".format(len(full_reports)))
    print("Open this in your browser to see the visual report timeline.")


def _cmd_report(args):
    report = load_report(args.id)
    if report:
        print(json.dumps(report, indent=2, default=str))
    else:
        print("Report not found: {}".format(args.id))


def _cmd_delete_report(args):
    success = delete_report(args.id)
    if success:
        print("Report deleted: {}".format(args.id))
    else:
        print("Report not found: {}".format(args.id))


def _cmd_clear_reports(args):
    if not args.force:
        confirm = input("Delete ALL reports? (y/N): ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return
    count = clear_reports()
    print("Deleted {} report(s).".format(count))


def _cmd_cache(args):
    if args.action == "stats":
        stats = get_cache_stats()
        print(json.dumps(stats, indent=2))
    elif args.action == "clear":
        clear_cache()
        print("Cache cleared.")
    elif args.action == "status":
        changed, unchanged, cache = get_changed_files()
        print("Changed files: {}".format(len(changed)))
        print("Unchanged files (cached): {}".format(len(unchanged)))
        if changed:
            print("\nChanged:")
            for f in changed[:10]:
                print("  {}".format(f))
            if len(changed) > 10:
                print("  ... and {} more".format(len(changed) - 10))


def _cmd_check(args):
    config = load_config()
    results, score = review_file(args.file, config, args.effort, args.fast)
    all_findings_list = []
    for r in results:
        for finding in r.findings:
            all_findings_list.append({
                "agent": finding.agent,
                "severity": finding.severity.value,
                "category": finding.category,
                "problem": finding.message,
                "file": finding.file,
                "line": finding.line,
                "suggestion": finding.suggestion,
                "suggested_code": finding.suggested_code,
                "confidence": finding.confidence,
                "rule_id": finding.rule_id,
            })

    if args.json:
        output = json_output(results, config, {args.file: score}, args.file)
        print(json.dumps(output, indent=2, default=str))
    else:
        report, blocking = format_report(results, config, {args.file: score})
        print(report)

        if args.prompt and blocking == 0:
            import sys as _sys
            if not _sys.stdin.isatty():
                print("(non-interactive mode - skipping prompts)")
            else:
                all_findings = [f for r in results for f in r.findings]
                non_blocking = [f for f in all_findings
                                if f.severity.value not in ("critical", "high")]
                if non_blocking:
                    print("\n" + "=" * 50)
                    print("Medium/Low findings detected:")
                    print("=" * 50)
                    for i, f in enumerate(non_blocking):
                        print("  [{}] {} {}".format(i + 1, f.severity.value.upper(), f.category))
                        print("      Problem: {}".format(f.message))
                        if f.suggestion:
                            print("      Suggestion: {}".format(f.suggestion))
                        if f.suggested_code:
                            print("      Code fix:")
                            for code_line in f.suggested_code.split("\n"):
                                print("        {}".format(code_line))
                        print("      File: {}:{}".format(f.file, f.line))
                        print()

                    print("What would you like to do?")
                    print("  a) Apply all auto-fixable changes")
                    print("  s) Skip all (commit as-is)")
                    print("  c) Cancel commit")

                    try:
                        choice = input("Enter your choice (a/s/c): ").strip().lower()
                        if choice == "a":
                            auto_fixable = get_auto_fixable(non_blocking)
                            if auto_fixable:
                                path = Path(args.file)
                                content = path.read_text(errors="ignore")
                                fixes = []
                                for f in auto_fixable:
                                    fixed = generate_fix(f, content)
                                    if fixed is not None:
                                        fixes.append((f, fixed))
                                if fixes:
                                    new_content = apply_fixes(fixes, content)
                                    path.write_text(new_content)
                                    print("Applied {} auto-fix(es).".format(len(fixes)))
                                else:
                                    print("No auto-fixable findings.")
                            else:
                                print("No auto-fixable findings.")
                        elif choice == "c":
                            print("Commit cancelled.")
                            _sys.exit(1)
                        else:
                            print("Skipping. Commit will proceed as-is.")
                    except EOFError:
                        print("No input available. Skipping.")

    if args.fix:
        all_findings = [f for r in results for f in r.findings]
        auto_fixable = get_auto_fixable(all_findings)
        if auto_fixable:
            path = Path(args.file)
            content = path.read_text(errors="ignore")
            fixes = []
            for f in auto_fixable:
                fixed = generate_fix(f, content)
                if fixed is not None:
                    fixes.append((f, fixed))
            if fixes:
                new_content = apply_fixes(fixes, content)
                path.write_text(new_content)
                if not args.json:
                    print("")
                    print("Applied {} auto-fix(es) to {}".format(len(fixes), args.file))
                    print("Review the changes before committing.")
            else:
                if not args.json:
                    print("")
                    print("No auto-fixable findings.")
        else:
            if not args.json:
                print("")
                print("No auto-fixable findings.")

    # Save report locally
    _, blocking = format_report(results, config, {args.file: score})
    commit_hash = ""
    branch = ""
    try:
        commit_hash = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True
        ).stdout.strip()
    except Exception:
        pass
    report_id = save_report(
        files_reviewed=[args.file],
        findings=all_findings_list,
        risk_score=score,
        blocking=blocking,
        commit_allowed=blocking == 0,
        commit_hash=commit_hash,
        branch=branch,
    )
    if not args.json:
        print("")
        print("Report saved: .prism-reports/{}.json".format(report_id))


def _cmd_check_staged(args):
    config = load_config()
    files = get_staged_files()
    if not files:
        print("No staged files to review.")
        return

    # Test execution (fast-path: changed files only)
    test_results = None
    if getattr(args, "test", False):
        print("Running tests on changed Python files...")
        test_results = run_changed_tests(files)
        if test_results.get("failed", 0) > 0:
            print("  [FAIL] {} test(s) failed".format(test_results["failed"]))
        elif test_results.get("passed", 0) > 0:
            print("  [PASS] {} test(s) passed".format(test_results["passed"]))
        else:
            print("  [INFO] {}".format(test_results.get("output", "no output")))

    # Use codebase cache to avoid re-scanning unchanged files
    try:
        changed, unchanged, cache = get_changed_files()
    except Exception:
        changed, unchanged, cache = files, [], {}

    files_to_review = []
    all_findings_list = []
    risk_scores = {}
    for f in files:
        cached = get_cached_findings(f, cache)
        if cached and f in unchanged:
            all_findings_list.extend(cached)
            risk_scores[f] = 0.0
            print("  [cached] {}".format(f))
        else:
            files_to_review.append(f)

    all_results = []
    if files_to_review:
        max_workers = min(5, len(files_to_review))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for f in files_to_review:
                diff = get_file_diff(f)
                futures[executor.submit(_review_one, f, config, args.effort, args.fast, diff)] = f

            for future in concurrent.futures.as_completed(futures):
                f = futures[future]
                try:
                    results, score, file_findings = future.result()
                    all_results.extend(results)
                    risk_scores[f] = score
                    all_findings_list.extend(file_findings)
                    cache_findings(f, file_findings, cache)
                    print("  [scanned] {}".format(f))
                except Exception as exc:
                    logger.error("Failed to review %s: %s", f, exc)
                    print("  [error] {}: {}".format(f, exc))

    report_text, blocking = format_report(all_results, config, risk_scores)
    print(report_text)
    commit_hash = ""
    branch = ""
    try:
        commit_hash = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True
        ).stdout.strip()
    except Exception:
        pass
    report_id = save_report(
        files_reviewed=files,
        findings=all_findings_list,
        risk_score=sum(risk_scores.values()) / max(len(risk_scores), 1),
        blocking=blocking,
        commit_allowed=blocking == 0,
        commit_hash=commit_hash,
        branch=branch,
    )
    if args.json:
        output = _json_output_staged(all_results, config, risk_scores, files,
                                     all_findings_list, blocking, test_results)
        print(json.dumps(output, indent=2, default=str))
    else:
        print("")
        print("Report saved: .prism-reports/{}.json".format(report_id))
        print("")
        print("=" * 50)
        print("  PRISM Review Complete")
        print("=" * 50)
        print("")
        print("Report ID: {}".format(report_id))
        print("Files reviewed: {}".format(len(files)))
        print("Findings: {}".format(len(all_findings_list)))
        print("")
        print("Next steps:")
        print("  prism reports       # review history")
        print("  prism dashboard     # visual timeline")
        print("  prism feedback      # feedback loop stats")

        if getattr(args, "dashboard", False):
            viewer = Path(__file__).parent / "dashboard.html"
            if viewer.exists():
                abs_path = str(viewer.resolve())
                print("")
                print("Dashboard: file:///{}".format(abs_path.replace("\\", "/")))
    sys.exit(1 if blocking > 0 else 0)


def _review_one(file_path, config, effort, fast, diff):
    """Review a single file. Returns (results, score, file_findings)."""
    results, score = review_file(file_path, config, effort, fast, diff)
    file_findings = []
    for r in results:
        for finding in r.findings:
            file_findings.append({
                "agent": finding.agent,
                "severity": finding.severity.value,
                "category": finding.category,
                "problem": finding.message,
                "file": finding.file,
                "line": finding.line,
                "suggestion": finding.suggestion,
                "suggested_code": finding.suggested_code,
                "confidence": finding.confidence,
                "rule_id": finding.rule_id,
            })
    return results, score, file_findings


def _json_output_staged(all_results, config, risk_scores, files,
                        all_findings_list, blocking, test_results=None):
    """Generate JSON output for check-staged - pure JSON, no banner text."""
    blocking_sev = set(config.get("block_on", ["critical", "high"]))
    conf_threshold = config.get("confidence_threshold", CONFIDENCE_THRESHOLD)
    policy = load_deviation_policy()

    all_findings = []
    for r in all_results:
        for f in r.findings:
            if f.confidence < conf_threshold:
                continue
            if is_deviation(f, policy):
                continue
            if f.rule_id and should_suppress(f.rule_id):
                continue
            all_findings.append({
                "agent": f.agent,
                "severity": f.severity.value,
                "category": f.category,
                "problem": f.message,
                "file": f.file,
                "line": f.line,
                "suggestion": f.suggestion,
                "suggested_code": f.suggested_code,
                "confidence": f.confidence,
                "rule_id": f.rule_id,
                "blocking": (
                    f.severity.value in blocking_sev
                    and f.blocker == Blocker.BLOCKS
                ),
            })

    gates_ok = quality_gates_met(all_results, config)

    commit_allowed = blocking == 0 and gates_ok
    if test_results and not test_results.get("ok", True):
        commit_allowed = False

    output = {
        "files_reviewed": files,
        "risk_scores": risk_scores,
        "total_findings": len(all_findings),
        "blocking": blocking,
        "quality_gates_passed": gates_ok,
        "commit_allowed": commit_allowed,
        "findings": all_findings,
    }
    if test_results is not None:
        output["tests"] = test_results
    return output
