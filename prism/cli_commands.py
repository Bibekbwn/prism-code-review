import json
import os
import subprocess
import sys
import tempfile
import concurrent.futures
from pathlib import Path

from prism import token_usage
from prism.agents import run_pipeline, quality_gates_met
from prism.ai_common import build_skeleton
from prism.feedback import record_commit, record_fix
from prism.autofix import generate_fix, get_auto_fixable
from prism.logging_config import logger
from prism.reports import save_report
from prism.codebase_cache import (
    get_cached_findings, get_changed_files, cache_findings,
)

from prism.cli_config import load_config, get_staged_files, run_changed_tests, get_file_diff, get_diff_files, get_diff_for_file
from prism.ignore import filter_files
from prism.cli_review import review_file, format_report, json_output

from prism.commands_common import (
    _git_commit_info, _agent_table, _set_agent_enabled, _save_config,
    _apply_fixes_with_preview, _cached_risk_score, _findings_to_agent_results,
    _empty_staged_output, _finalize_review, _review_one, _finding_to_dict,
    _dashboard_enabled,
)

# The command handlers live in the sibling modules, but this module is the
# documented import location for them (``from prism.cli_commands import
# _cmd_check``), so they are re-exported here rather than at every call site.
from prism.commands_reports import (
    _cmd_reports, _cmd_report, _cmd_delete_report, _cmd_clear_reports,
    _cmd_dashboard, _cmd_stats, _cmd_config, _cmd_policy, _cmd_feedback,
    _cmd_suppressed, _cmd_cache,
)
from prism.commands_setup import (
    _cmd_key, _is_placeholder_value, _get_active_provider, _cmd_init,
    _cmd_install_hook, _cmd_uninstall_hook, _cmd_version, _cmd_help,
    _cmd_agents, _cmd_ignore, _cmd_mode, _cmd_doctor,
)

__all__ = [
    "_run_self_tests", "_run_benchmark", "_cmd_check", "_cmd_check_staged",
    "_cmd_check_diff", "_cmd_scan", "_cmd_reports", "_cmd_report",
    "_cmd_delete_report",
    "_cmd_clear_reports", "_cmd_dashboard", "_cmd_stats", "_cmd_config",
    "_cmd_policy", "_cmd_feedback", "_cmd_suppressed", "_cmd_cache", "_cmd_key",
    "_is_placeholder_value", "_get_active_provider", "_cmd_init",
    "_cmd_install_hook", "_cmd_uninstall_hook", "_cmd_version", "_cmd_help",
    "_cmd_agents", "_cmd_ignore", "_cmd_mode", "_cmd_doctor",
    "_git_commit_info", "_agent_table", "_set_agent_enabled", "_save_config",
    "_apply_fixes_with_preview",
    "_cached_risk_score", "_findings_to_agent_results", "_empty_staged_output",
    "_finalize_review", "_review_one",
]


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
            verify_findings, build_import_graph,
            get_cross_file_context,
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


def _collect_fixes(file_path, findings):
    """Return (path, content, fixes) for findings the autofix engine can apply."""
    path = Path(file_path)
    try:
        content = path.read_text(errors="ignore")
    except OSError:
        return path, "", []
    fixes = []
    for f in findings:
        fixed = generate_fix(f, content)
        if fixed is not None:
            fixes.append((f, fixed))
    return path, content, fixes


def _check_prompt_fixes(args, results):
    """Offer auto-fixes for medium/low findings (prism check --prompt)."""
    all_findings = [f for r in results for f in r.findings]
    non_blocking = [f for f in all_findings
                    if f.severity.value not in ("critical", "high")]
    if not non_blocking:
        return

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

    # One-line prompt: the old multi-line menu was printed even when stdin was
    # closed, then abandoned at the EOF.
    try:
        choice = input(
            "What would you like to do? "
            "(a)pply auto-fixes / (s)kip / (c)ancel [s]: "
        ).strip().lower()
    except EOFError:
        print("(non-interactive mode - skipping prompts)")
        choice = "s"

    if choice == "a":
        auto_fixable = get_auto_fixable(non_blocking)
        path, content, fixes = _collect_fixes(args.file, auto_fixable)
        if not fixes:
            print("No auto-fixable findings.")
            return
        if _apply_fixes_with_preview(path, content, fixes, assume_yes=True):
            for fixed_finding, _ in fixes:
                record_fix(fixed_finding.rule_id or "", True)
            print("Applied {} auto-fix(es).".format(len(fixes)))
        else:
            print("No auto-fixable changes written.")
    elif choice == "c":
        print("Commit cancelled.")
        sys.exit(1)
    else:
        print("Skipping. Commit will proceed as-is.")


def _check_direct_fixes(args, results):
    """Apply auto-fixes for ``prism check --fix`` (no prompt)."""
    auto_fixable = get_auto_fixable([f for r in results for f in r.findings])
    path, content, fixes = _collect_fixes(args.file, auto_fixable)
    if not fixes:
        if not args.json:
            print("")
            print("No auto-fixable findings.")
        return
    applied = _apply_fixes_with_preview(
        path, content, fixes,
        assume_yes=getattr(args, "yes", False),
        json_mode=bool(getattr(args, "json", False)),
    )
    if applied:
        for fixed_finding, _ in fixes:
            record_fix(fixed_finding.rule_id or "", True)
        if not args.json:
            print("Applied {} auto-fix(es) to {}".format(len(fixes), args.file))
            print("Review the changes before committing.")


def _save_check_report(args, results, config, score, all_findings_list):
    """Persist the single-file report and exit with the commit decision."""
    _, blocking = format_report(results, config, {args.file: score})
    gates_ok = quality_gates_met(results, config)
    allowed = blocking == 0 and gates_ok
    commit_hash, branch = _git_commit_info()
    report_id = save_report(
        files_reviewed=[args.file],
        findings=all_findings_list,
        risk_score=score,
        blocking=blocking,
        commit_allowed=allowed,
        commit_hash=commit_hash,
        branch=branch,
        # Keep the persisted report in step with the --json output and the
        # dashboard, which all read this same ledger snapshot.
        token_usage=token_usage.summary(),
    )
    record_commit(all_findings_list, commit_hash)
    if not args.json:
        print("")
        print(token_usage.format_summary())
        print("Report saved: .prism-reports/{}.json".format(report_id))
        # Consistent with check-staged/check-diff: open the dashboard unless
        # the developer opted out (or we are in CI / non-interactive).
        if _dashboard_enabled(args):
            from prism.commands_reports import build_dashboard
            build_dashboard(open_browser=True)
    sys.exit(0 if allowed else 1)


def _cmd_check(args):
    if not Path(args.file).exists():
        message = "File not found: {}".format(args.file)
        # A JSON consumer (CI, IDE) must never receive prose: emit a valid
        # envelope and keep the non-zero exit code for the error itself.
        if getattr(args, "json", False):
            print(json.dumps({
                "file": args.file,
                "error": message,
                "total_findings": 0,
                "blocking": 0,
                "quality_gates_passed": True,
                "commit_allowed": True,
                "findings": [],
            }, indent=2))
        else:
            print(message, file=sys.stderr)
        sys.exit(2)

    config = load_config()
    token_usage.reset()
    results, score = review_file(args.file, config, args.effort, args.fast)
    try:
        content = Path(args.file).read_text(errors="ignore")
    except OSError:
        content = ""
    all_findings_list = [
        _finding_to_dict(f, content)
        for r in results
        for f in r.findings
    ]

    if args.json:
        output = json_output(results, config, {args.file: score}, args.file)
        output["token_usage"] = token_usage.summary()
        print(json.dumps(output, indent=2, default=str))
    else:
        report, blocking = format_report(results, config, {args.file: score})
        print(report)

    if args.prompt and blocking == 0:
        if not sys.stdin.isatty():
            print("(non-interactive mode - skipping prompts)")
        else:
            _check_prompt_fixes(args, results)

    if args.fix:
        _check_direct_fixes(args, results)

    _save_check_report(args, results, config, score, all_findings_list)


def _prompt_staged_fixes(all_results, config):
    """Offer to apply auto-fixes for medium/low findings before finalizing.

    Mirrors ``prism check --prompt`` for a multi-file staged review. It only
    runs when there are no blocking findings (a blocked commit should be fixed
    by the developer, not auto-patched) and stdin is a terminal.
    """
    findings = [f for r in all_results for f in r.findings]
    blocking_sev = set(config.get("block_on", ["critical", "high"]))
    if any(f.blocker.value == "blocks" and f.severity.value in blocking_sev
           for f in findings):
        return

    non_blocking = [f for f in findings
                    if f.severity.value not in ("critical", "high")]
    auto_fixable = get_auto_fixable(non_blocking)
    if not auto_fixable:
        return
    if not sys.stdin.isatty():
        print("(non-interactive mode - skipping prompts)")
        return

    by_file = {}
    for f in auto_fixable:
        by_file.setdefault(f.file, []).append(f)

    print("")
    print("=" * 50)
    print("Auto-fixable medium/low findings:")
    print("=" * 50)
    for f in auto_fixable:
        print("  [{}] {} {}:{}".format(
            f.severity.value.upper(), f.rule_id, f.file, f.line))
        print("      {}".format(f.message))
        if f.suggested_code:
            for code_line in f.suggested_code.split("\n"):
                print("        {}".format(code_line))

    try:
        choice = input(
            "Apply {} auto-fix(es)? (y/N) ".format(len(auto_fixable))
        ).strip().lower()
    except EOFError:
        print("(non-interactive mode - skipping prompts)")
        return
    if choice not in ("y", "yes"):
        print("Skipping. Commit will proceed as-is.")
        return

    applied = 0
    fixed_paths = []
    for path_str, fs in by_file.items():
        path = Path(path_str)
        if not path.exists():
            continue
        content = path.read_text(errors="ignore")
        fixes = []
        for f in fs:
            fixed = generate_fix(f, content)
            if fixed is not None:
                fixes.append((f, fixed))
        if not fixes:
            continue
        if _apply_fixes_with_preview(path, content, fixes, assume_yes=True):
            for fixed_finding, _ in fixes:
                record_fix(fixed_finding.rule_id or "", True)
            applied += len(fixes)
            fixed_paths.append(str(path))

    if applied:
        print("Applied {} auto-fix(es).".format(applied))
        # The fix rewrote the working tree but the index still holds the old
        # content, so the commit would ship the unfixed version. Re-stage.
        if _restage(fixed_paths):
            print("Re-staged {} file(s) for commit.".format(len(fixed_paths)))
        else:
            print("Could not re-stage; run `git add` before committing.")
    else:
        print("No auto-fixable changes written.")
    return fixed_paths


def _restage(paths):
    """``git add`` the given files so a commit includes the applied fixes."""
    try:
        proc = subprocess.run(
            ["git", "add", "--"] + list(paths),
            capture_output=True, text=True)
        return proc.returncode == 0
    except Exception:
        return False


def _review_and_store(f, per_file, cache, config, args, use_diff=True):
    """Review one staged file and store its result for the final report."""
    diff = get_file_diff(f) if use_diff else ""
    results, score, file_findings = _review_one(
        f, config, args.effort, args.fast, diff)
    per_file[f] = {
        "findings": list(file_findings),
        "results": results,
        "score": score,
    }
    cache_findings(f, file_findings, cache)


def _review_staged_parallel(files_to_review, per_file, cache, config, args,
                            status, use_diff=True):
    """Review files concurrently (max 5 workers) and record progress."""
    if not files_to_review:
        return
    max_workers = min(5, len(files_to_review))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_review_and_store, f, per_file, cache, config,
                            args, use_diff): f
            for f in files_to_review
        }
        for future in concurrent.futures.as_completed(futures):
            f = futures[future]
            try:
                future.result()
                status("  [scanned] {}".format(f))
            except Exception as exc:
                logger.error("Failed to review %s: %s", f, exc)
                status("  [error] {}: {}".format(f, exc))


def _cmd_check_staged(args):
    json_mode = bool(getattr(args, "json", False))
    token_usage.reset()

    def _status(msg):
        print(msg, file=sys.stderr if json_mode else sys.stdout)

    config = load_config()
    staged = get_staged_files(apply_ignore=False)
    files, skipped = filter_files(staged)
    if skipped:
        _status("Skipped (ignored): {}".format(", ".join(skipped)))
    if not files:
        if json_mode:
            print(json.dumps(_empty_staged_output(files, skipped), indent=2))
        else:
            _status("No staged files to review.")
        sys.exit(0)

    # Test execution (fast-path: changed files only)
    test_results = None
    if getattr(args, "test", False):
        _status("Running tests on changed Python files...")
        test_results = run_changed_tests(files)
        if test_results.get("failed", 0) > 0:
            _status("  [FAIL] {} test(s) failed".format(test_results["failed"]))
        elif test_results.get("passed", 0) > 0:
            _status("  [PASS] {} test(s) passed".format(test_results["passed"]))
        else:
            _status("  [INFO] {}".format(test_results.get("output", "no output")))

    # Use the codebase cache to skip re-scanning files that did not change
    try:
        _changed, unchanged, cache = get_changed_files()
    except Exception:
        unchanged, cache = [], {}

    # Track results per file so a post-fix re-review can replace just that
    # file's findings before the report is written.
    per_file = {}
    files_to_review = []
    for f in files:
        cached = get_cached_findings(f, cache)
        # An empty list is a valid cache entry (file reviewed, no findings),
        # so test for None rather than truthiness.
        if cached is not None and f in unchanged:
            per_file[f] = {
                "findings": list(cached),
                "results": _findings_to_agent_results(cached),
                "score": _cached_risk_score(f, cached),
            }
            _status("  [cached] {}".format(f))
        else:
            files_to_review.append(f)

    _review_staged_parallel(files_to_review, per_file, cache, config, args,
                            _status)

    if getattr(args, "prompt", False) and not json_mode:
        fixed = _prompt_staged_fixes(
            [r for entry in per_file.values() for r in entry["results"]], config)
        # Re-review the fixed files so the report reflects post-fix state.
        for f in fixed or []:
            try:
                _review_and_store(f, per_file, cache, config, args)
                _status("  [re-reviewed] {}".format(f))
            except Exception as exc:
                logger.error("Failed to re-review %s: %s", f, exc)

    all_results = [r for entry in per_file.values() for r in entry["results"]]
    all_findings_list = [x for entry in per_file.values()
                         for x in entry["findings"]]
    risk_scores = {f: entry["score"] for f, entry in per_file.items()}

    _finalize_review(all_results, all_findings_list, risk_scores, files,
                     config, json_mode, test_results, args)


def _cmd_check_diff(args):
    """Review the diff between a base ref and HEAD (PR-style review)."""
    json_mode = bool(getattr(args, "json", False))
    token_usage.reset()

    def _status(msg):
        print(msg, file=sys.stderr if json_mode else sys.stdout)

    base = getattr(args, "base", None) or os.getenv("PRISM_BASE") or "origin/main"

    def _ref_ok(ref):
        try:
            return subprocess.run(
                ["git", "rev-parse", "--verify", ref],
                capture_output=True, text=True
            ).returncode == 0
        except Exception:
            return False

    if not _ref_ok(base):
        for candidate in ("origin/HEAD", "origin/main", "origin/master", "HEAD~1"):
            if _ref_ok(candidate):
                base = candidate
                break
        else:
            print("Cannot resolve base ref '{}'".format(base), file=sys.stderr)
            sys.exit(2)

    files = [f for f in get_diff_files(base) if Path(f).exists()]
    # check-staged honours .prismignore (get_staged_files applies it); check-diff
    # must do the same or a docs-only PR fails the review on README wording.
    files, skipped = filter_files(files)
    if skipped:
        _status("Skipped (ignored): {} file(s)".format(len(skipped)))
    if not files:
        if json_mode:
            print(json.dumps(_empty_staged_output(files, skipped), indent=2))
        else:
            _status("No changed files to review.")
        sys.exit(0)

    config = load_config()
    all_results = []
    all_findings_list = []
    risk_scores = {}
    for f in files:
        diff = get_diff_for_file(base, f)
        try:
            results, score, file_findings = _review_one(
                f, config, args.effort, args.fast, diff
            )
        except Exception as exc:
            logger.error("Failed to review %s: %s", f, exc)
            _status("  [error] {}: {}".format(f, exc))
            continue
        all_results.extend(results)
        risk_scores[f] = score
        all_findings_list.extend(file_findings)
        _status("  [scanned] {}".format(f))

    _finalize_review(all_results, all_findings_list, risk_scores, files,
                     config, json_mode, args=args)


def _cmd_scan(args):
    """Review every source file under a path (whole-project audit).

    Unlike ``check-staged``/``check-diff``, this reviews the full file content
    (no diff) so it is useful for onboarding a big project or a nightly audit.
    The ignore list and codebase cache still apply, so unchanged files are
    skipped on repeat runs.
    """
    json_mode = bool(getattr(args, "json", False))
    token_usage.reset()

    def _status(msg):
        print(msg, file=sys.stderr if json_mode else sys.stdout)

    root = Path(getattr(args, "path", None) or ".")
    if not root.exists():
        print("Path not found: {}".format(root), file=sys.stderr)
        sys.exit(2)

    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                 ".mypy_cache", ".pytest_cache", "dist", "build"}
    files = [
        str(p).replace("\\", "/") for p in sorted(root.rglob("*"))
        if p.is_file() and not (set(p.parts) & skip_dirs)
    ]
    files, skipped = filter_files(files)
    if skipped:
        _status("Skipped (ignored): {} file(s)".format(len(skipped)))
    if not files:
        if json_mode:
            print(json.dumps(_empty_staged_output(files, skipped), indent=2))
        else:
            _status("No reviewable files found under {}.".format(root))
        sys.exit(0)

    config = load_config()
    try:
        _changed, unchanged, cache = get_changed_files()
    except Exception:
        unchanged, cache = [], {}

    per_file = {}
    files_to_review = []
    for f in files:
        cached = get_cached_findings(f, cache)
        # An empty list is a valid cache entry (file reviewed, no findings),
        # so test for None rather than truthiness.
        if cached is not None and f in unchanged:
            per_file[f] = {
                "findings": list(cached),
                "results": _findings_to_agent_results(cached),
                "score": _cached_risk_score(f, cached),
            }
        else:
            files_to_review.append(f)

    _status("Scanning {} file(s) under {}...".format(len(files), root))
    _review_staged_parallel(files_to_review, per_file, cache, config, args,
                            _status, use_diff=False)

    all_results = [r for entry in per_file.values() for r in entry["results"]]
    all_findings_list = [x for entry in per_file.values()
                         for x in entry["findings"]]
    risk_scores = {f: entry["score"] for f, entry in per_file.items()}
    _status("Scanned {} file(s), {} finding(s).".format(
        len(per_file), len(all_findings_list)))

    _finalize_review(all_results, all_findings_list, risk_scores, files,
                     config, json_mode, None, args, audit=True)
