import argparse
import json
import os
import sys
import subprocess
import concurrent.futures
from pathlib import Path

# Add parent directory to path so prism imports work when run as executable
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load .env file if it exists (for GEMINI_API_KEY and other settings)
try:
    from dotenv import load_dotenv
    # Try multiple locations for .env
    for env_path in [
        Path(__file__).parent.parent.parent / ".env",
        Path(__file__).parent.parent / ".env",
        Path.cwd() / ".env",
    ]:
        if env_path.exists():
            load_dotenv(env_path)
            break
except ImportError:
    pass

from prism.agents import (
    AGENT_REGISTRY, Finding, Severity, Blocker, run_pipeline,
    risk_score, quality_gates_met,
)
from prism.ai_common import build_skeleton
from prism.ai_security import AISecurityAgent
from prism.ai_quality import AIQualityAgent
from prism.ai_policy import AIPolicyAgent
from prism.ai_test import AITestAgent
from prism.ai_architecture import AIArchitectureAgent
from prism.ai_performance import AIPerformanceAgent
from prism.feedback import load_feedback, should_suppress, suppress_summary, scan_dependencies
from prism.autofix import generate_fix, apply_fixes, get_auto_fixable
from prism.logging_config import logger
from prism.reports import save_report, load_report
from prism.codebase_cache import (
    get_cached_findings, get_changed_files, cache_findings,
    get_cache_stats, clear_cache,
)

DEFAULT_AGENTS = ['ai_security', 'ai_quality', 'ai_policy', 'ai_test', 'ai_architecture', 'ai_performance']
CONFIDENCE_THRESHOLD = 0.7


def load_config():
    for name in ['prism.json', '.prism.json']:
        p = Path(name)
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {
        'agents': DEFAULT_AGENTS,
        'block_on': ['critical', 'high'],
        'quality_gates': {
            'max_complexity': 10,
            'max_file_length': 500,
            'min_coverage': 0,
        },
        'confidence_threshold': CONFIDENCE_THRESHOLD,
    }


def load_deviation_policy():
    for name in ['.prism-policy.json', 'prism-policy.json']:
        p = Path(name)
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {'deviations': []}


def get_staged_files():
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
        capture_output=True, text=True
    )
    return [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]


def run_changed_tests(changed_files, timeout=120):
    """Run pytest on changed Python files.

    Returns a dict with test execution results:
      - ok: bool — did tests pass
      - passed: int — tests passed
      - failed: int — tests failed
      - files: list of changed .py files tested
      - output: str — pytest output (last 2000 chars)
      - error: str — if pytest itself crashed

    This closes the "test execution" gap — CodeRabbit runs tests and reports
    real failures. We run only on changed files (fast-path) so it's cheap
    enough for a pre-commit hook.
    """
    import re
    py_files = [f for f in changed_files if f.endswith('.py')]
    if not py_files:
        return {"ok": True, "passed": 0, "failed": 0, "files": [],
                "output": "No Python files changed", "error": None}

    try:
        result = subprocess.run(
            ['python', '-m', 'pytest'] + py_files + ['-q', '--no-header'],
            capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout + result.stderr)[-2000:]
        passed, failed = 0, 0
        m_pass = re.search(r'(\d+)\s+passed', output)
        m_fail = re.search(r'(\d+)\s+failed', output)
        if m_pass:
            passed = int(m_pass.group(1))
        if m_fail:
            failed = int(m_fail.group(1))

        return {
            "ok": result.returncode == 0,
            "passed": passed,
            "failed": failed,
            "files": py_files,
            "output": output,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False, "passed": 0, "failed": 0, "files": py_files,
            "output": "pytest timed out after {}s".format(timeout),
            "error": "timeout",
        }
    except Exception as exc:
        return {
            "ok": False, "passed": 0, "failed": 0, "files": py_files,
            "output": str(exc),
            "error": str(exc),
        }


def get_file_diff(file_path, context_lines=3):
    """Get the git diff for a file (staged + unstaged changes)."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--unified={}'.format(context_lines),
             '--', file_path],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except Exception:
        pass
    return ""


def review_file(file_path, config, effort='balanced', fast=False, diff=""):
    path = Path(file_path)
    if not path.exists():
        return [], 0.0
    content = path.read_text(errors='ignore')
    skeleton = build_skeleton(file_path, content)
    line_count = content.count("\n") + 1
    agents = list(config.get('agents', DEFAULT_AGENTS))
    results = run_pipeline(agents, file_path, content, diff, skeleton,
                           line_count=line_count, fast=fast)

    # Run SCA dependency scan
    sca_findings = scan_dependencies(file_path, content)
    if sca_findings:
        from prism.agents import Finding, Severity, Blocker
        sca_results = []
        for item in sca_findings:
            f = Finding(
                agent="sca",
                severity=Severity(item["severity"]),
                category=item["category"],
                message=item["message"],
                file=item["file"],
                suggestion=item.get("suggestion"),
                blocker=Blocker.BLOCKS if item["severity"] in ("critical", "high") else Blocker.WARNS,
                confidence=item.get("confidence", 0.95),
                rule_id=item["rule_id"],
            )
            sca_results.append(f)
        if sca_results:
            from prism.agents import AgentResult
            results.append(AgentResult(
                agent_name="sca",
                findings=sca_results,
                passed=not any(f.blocker == Blocker.BLOCKS for f in sca_results),
                duration_ms=0.0,
            ))

    score = risk_score(file_path, content, content)
    return results, score


def is_deviation(finding, policy):
    for dev in policy.get('deviations', []):
        if (dev.get('rule_id') == finding.rule_id
            and dev.get('file', finding.file) == finding.file):
            return True
    return False


def format_report(results, config, risk_scores=None):
    lines = []
    blocking_sev = set(config.get('block_on', ['critical', 'high']))
    conf_threshold = config.get('confidence_threshold', CONFIDENCE_THRESHOLD)
    policy = load_deviation_policy()

    total = 0
    blocking_count = 0
    warn_count = 0
    skipped = 0

    for r in results:
        if not r.findings:
            continue
        lines.append("  [{}] {} finding(s) ({}ms)".format(
            r.agent_name, len(r.findings), int(r.duration_ms)))
        for f in r.findings:
            if f.confidence < conf_threshold:
                skipped += 1
                continue
            if is_deviation(f, policy):
                skipped += 1
                continue
            if f.rule_id and should_suppress(f.rule_id):
                skipped += 1
                continue
            total += 1
            is_blocking = (
                f.severity.value in blocking_sev
                and f.blocker == Blocker.BLOCKS
            )
            if is_blocking:
                blocking_count += 1
            else:
                warn_count += 1
            tag = 'BLOCK' if is_blocking else 'WARN'
            lines.append("    [{}] {} {} [{}] conf={:.0f}%".format(
                tag, f.severity.value.upper(), f.category,
                f.rule_id or 'N/A', f.confidence * 100))
            lines.append("         Problem: {}".format(f.message))
            loc = "{}:{}".format(f.file, f.line) if f.line else f.file
            lines.append("         at {}".format(loc))
            if f.suggestion:
                lines.append("         Suggestion: {}".format(f.suggestion))
            if f.suggested_code:
                lines.append("         Code fix:")
                for code_line in f.suggested_code.split("\n"):
                    lines.append("           {}".format(code_line))

    lines.append("")
    lines.append("PRISM Review Report")
    lines.append("")
    lines.append("Total findings: {}".format(total))
    lines.append("  Blocking: {}".format(blocking_count))
    lines.append("  Warnings: {}".format(warn_count))
    lines.append("  Skipped (low confidence / deviation): {}".format(skipped))

    if risk_scores:
        lines.append("")
        lines.append("Risk Scores:")
        for fname, score in risk_scores.items():
            bar = '#' * int(score * 20) + '-' * (20 - int(score * 20))
            lines.append("  {} [{}] {:.0%}".format(fname, bar, score))

    gates_ok = quality_gates_met(results, config)
    if not gates_ok:
        lines.append("")
        lines.append("QUALITY GATES: FAILED")

    if blocking_count > 0 or not gates_ok:
        lines.append("")
        lines.append("COMMIT BLOCKED - resolve {} issue(s) before pushing.".format(
            blocking_count))
    else:
        lines.append("")
        lines.append("All checks passed.")

    return '\n'.join(lines), blocking_count


def _json_output(results, config, risk_scores, file_path):
    """Generate JSON output for IDE/CI integration."""
    blocking_sev = set(config.get('block_on', ['critical', 'high']))
    conf_threshold = config.get('confidence_threshold', CONFIDENCE_THRESHOLD)
    policy = load_deviation_policy()

    all_findings = []
    for r in results:
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

    blocking_count = sum(1 for f in all_findings if f["blocking"])
    gates_ok = quality_gates_met(results, config)

    return {
        "file": file_path,
        "risk_score": risk_scores.get(file_path, 0.0),
        "total_findings": len(all_findings),
        "blocking": blocking_count,
        "quality_gates_passed": gates_ok,
        "commit_allowed": blocking_count == 0 and gates_ok,
        "findings": all_findings,
    }


def _json_output_staged(all_results, config, risk_scores, files,
                         all_findings_list, blocking, test_results=None):
    """Generate JSON output for check-staged — pure JSON, no banner text."""
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

    # If tests were run and failed, block the commit
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


def _review_one(file_path, config, effort, fast, diff):
    """Review a single file. Returns (results, score, file_findings)."""
    results, score = review_file(file_path, config, effort, fast, diff)
    file_findings = []
    for r in results:
        for finding in r.findings:
            file_findings.append({
                'agent': finding.agent,
                'severity': finding.severity.value,
                'category': finding.category,
                'problem': finding.message,
                'file': finding.file,
                'line': finding.line,
                'suggestion': finding.suggestion,
                'suggested_code': finding.suggested_code,
                'confidence': finding.confidence,
                'rule_id': finding.rule_id,
            })
    return results, score, file_findings


def _run_self_tests(quick=False):
    """Run self-tests to verify the system works correctly."""
    import tempfile, pathlib, os
    
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
    
    # Test 1: Imports
    try:
        from prism.ai_common import (
            build_skeleton, chunk_content, get_tier_for_file,
            review_with_agent, verify_findings, build_import_graph,
            get_cross_file_context, parse_findings, call_gemini,
            API_TIMEOUT, MAX_CONTENT_CHARS
        )
        check("imports", True)
    except Exception as e:
        check("imports: {}".format(e), False)
        return
    
    # Test 2: Skeleton builder
    sk = build_skeleton('test.py', 'import os\nclass Foo:\n    def bar(self): pass')
    check("skeleton builder", 'File: test.py' in sk and 'Class Foo' in sk)
    
    # Test 3: Non-Python file
    check("non-python skeleton", build_skeleton('test.md', '# Hello') == '')
    
    # Test 4: Chunking
    content = '\n'.join(['line {}'.format(i) for i in range(1, 501)])
    chunks = chunk_content(content, max_lines=400, overlap=20)
    check("chunking 500 lines -> 2 chunks", len(chunks) == 2)
    
    # Test 5: Tier logic
    check("tier 100 lines", get_tier_for_file(100)[0] == 1.0)
    check("tier 500 lines", get_tier_for_file(500)[0] == 1.5)
    check("tier 5000 lines", get_tier_for_file(5000)[0] == 2.0)
    check("tier 15000 lines", get_tier_for_file(15000)[0] == 3.0)
    
    # Test 6: Verification
    from prism.agents import Finding, Severity, Blocker
    findings = [Finding(
        agent='test', severity=Severity.HIGH, category='C',
        message='test', file='test.py', line=999,
        suggestion='fix', blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id='TEST-AI-001'
    )]
    result = verify_findings(findings, 'test.py', 'x = 1\n')
    check("verify drops out-of-bounds", len(result) == 0)
    
    # Test 7: Import graph
    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp)
        (p / 'a.py').write_text('import b\ndef foo(): pass\n')
        (p / 'b.py').write_text('def bar(): pass\n')
        graph = build_import_graph(tmp)
        check("import graph has 2 files", len(graph) == 2)
        ctx = get_cross_file_context(str(p / 'a.py'), graph, tmp)
        check("cross-file context", 'imports' in ctx.lower() or 'import' in ctx.lower())
    
    # Test 8: Agent registry — import all agents first, then check
    from prism.agents import AGENT_REGISTRY, register_agent
    # Force import all agent modules to trigger @register_agent decorators
    import importlib
    for mod_name in [
        'prism.ai_security', 'prism.ai_quality', 'prism.ai_policy',
        'prism.ai_test', 'prism.ai_architecture', 'prism.ai_performance',
        'prism.agents_security', 'prism.agents_quality',
        'prism.agents_policy', 'prism.agents_test', 'prism.agents_ai',
    ]:
        importlib.import_module(mod_name)
    check("10+ agents registered", len(AGENT_REGISTRY) >= 10)
    
    # Test 9: Config
    config = load_config()
    check("config has agents", 'agents' in config)
    
    # Test 10: CLI pipeline (if not quick)
    if not quick:
        try:
            from prism.agents import run_pipeline
            from prism.ai_common import build_skeleton
            code = 'x = 1\ny = 2\n'
            with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
                f.write(code)
                path = f.name
            sk = build_skeleton(path, code)
            results = run_pipeline(['security', 'quality'], path, code, code, sk)
            check("pipeline runs", len(results) == 2)
            os.unlink(path)
        except Exception as e:
            check("pipeline: {}".format(e), False)
    
    print()
    print("Results: {} passed, {} failed".format(passed, failed))
    if failed > 0:
        sys.exit(1)


def _run_benchmark(file_path, iterations):
    """Benchmark agent performance on a file."""
    import time
    
    if not file_path:
        print("Please specify a file: prism benchmark --file <path>")
        return
    
    path = Path(file_path)
    if not path.exists():
        print("File not found: {}".format(file_path))
        return
    
    content = path.read_text(errors='ignore')
    from prism.ai_common import build_skeleton
    sk = build_skeleton(file_path, content)
    
    print("PRISM Benchmark: {}".format(file_path))
    print("=" * 50)
    print("File size: {} lines, {} chars".format(content.count('\n') + 1, len(content)))
    print("Iterations: {}".format(iterations))
    print()
    
    from prism.agents import run_pipeline
    agents = ['security', 'quality', 'policy', 'test']
    
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
        print()


def main():
    parser = argparse.ArgumentParser(prog='prism', description='PRISM - Pre-Commit Code Review')
    parser.add_argument('--effort', choices=['lite', 'balanced', 'max'],
                        default='balanced', help='AI review effort level')
    sub = parser.add_subparsers(dest='command')

    check = sub.add_parser('check', help='Review a file')
    check.add_argument('file', help='File to review')
    check.add_argument('--fix', action='store_true',
                        help='Apply auto-fixable changes')
    check.add_argument('--json', action='store_true',
                        help='Output results as JSON')
    check.add_argument('--prompt', action='store_true',
                        help='Ask developer about medium/low findings')
    check.add_argument('--effort', choices=['lite', 'balanced', 'max'],
                        default='balanced', help='AI review effort level')
    check.add_argument('--fast', action='store_true',
                        help='Use two-pass summarization for large files (faster, less thorough)')

    check_staged = sub.add_parser('check-staged', help='Review staged git changes')
    check_staged.add_argument('--json', action='store_true',
                               help='Output results as JSON')
    check_staged.add_argument('--prompt', action='store_true',
                               help='Ask developer about medium/low findings')
    check_staged.add_argument('--effort', choices=['lite', 'balanced', 'max'],
                               default='balanced', help='AI review effort level')
    check_staged.add_argument('--fast', action='store_true',
                          help='Use two-pass summarization for large files')
    check_staged.add_argument('--dashboard', action='store_true',
                         help='Open visual dashboard after review')
    check_staged.add_argument('--test', action='store_true',
                         help='Run pytest on changed Python files before review')
    sub.add_parser('init', help='Create prism.json config')
    sub.add_parser('install-hook', help='Install pre-commit hook')
    sub.add_parser('policy', help='Show deviation policy')
    sub.add_parser('feedback', help='Show feedback loop stats')
    sub.add_parser('suppressed', help='Show historically suppressed rules')
    sub.add_parser('reports', help='Show review history')
    sub.add_parser('report', help='Show a specific report by ID').add_argument('id')
    sub.add_parser('dashboard', help='Open visual report dashboard in browser')
    
    # Report management
    delete_cmd = sub.add_parser('delete-report', help='Delete a specific report')
    delete_cmd.add_argument('id', help='Report ID to delete')
    clear_cmd = sub.add_parser('clear-reports', help='Delete ALL reports')
    clear_cmd.add_argument('--force', action='store_true', help='Skip confirmation')
    
    # Agent management
    agents_cmd = sub.add_parser('agents', help='List available agents')
    agents_cmd.add_argument('--enable', help='Enable a specific agent')
    agents_cmd.add_argument('--disable', help='Disable a specific agent')
    
    # Help command
    sub.add_parser('help', help='Show all commands and their uses')
    
    # Version command
    sub.add_parser('version', help='Show PRISM version')
    
    # Uninstall-hook command
    sub.add_parser('uninstall-hook', help='Remove pre-commit hook')
    
    # Stats command
    sub.add_parser('stats', help='Show review statistics')
    
    # Config command
    config_cmd = sub.add_parser('config', help='Show or manage configuration')
    config_cmd.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'), help='Set a config value')
    config_cmd.add_argument('--get', metavar='KEY', help='Get a config value')
    
    # Test command (self-test)
    test_cmd = sub.add_parser('test', help='Run self-tests to verify the system works')
    test_cmd.add_argument('--quick', action='store_true', help='Run only quick tests (skip API calls)')
    
    # Benchmark command
    benchmark_cmd = sub.add_parser('benchmark', help='Benchmark agent performance')
    benchmark_cmd.add_argument('--file', help='File to benchmark against')
    benchmark_cmd.add_argument('--iterations', type=int, default=3, help='Number of iterations')

    args = parser.parse_args()

    if args.command == 'agents':
        for name, agent in AGENT_REGISTRY.items():
            print("  {}: {}".format(name, agent.description))
        
        if getattr(args, 'enable', None):
            config = load_config()
            if args.enable not in config.get('agents', DEFAULT_AGENTS):
                config.setdefault('agents', DEFAULT_AGENTS).append(args.enable)
                with open('prism.json', 'w') as f:
                    json.dump(config, f, indent=2)
                print("Enabled agent: {}".format(args.enable))
            else:
                print("Agent already enabled: {}".format(args.enable))
        
        if getattr(args, 'disable', None):
            config = load_config()
            agents = config.get('agents', DEFAULT_AGENTS)
            if args.disable in agents:
                agents.remove(args.disable)
                config['agents'] = agents
                with open('prism.json', 'w') as f:
                    json.dump(config, f, indent=2)
                print("Disabled agent: {}".format(args.disable))
            else:
                print("Agent not found: {}".format(args.disable))
        return

    if args.command == 'help':
        print("""
PRISM - Pre-Commit Code Review System
=====================================

USAGE:
    prism <command> [options]

CORE REVIEW COMMANDS:
    prism check <file>              Review a single file with all AI agents
    prism check <file> --json       Output results as JSON
    prism check <file> --prompt     Ask about medium/low findings interactively
    prism check <file> --fix        Apply auto-fixable changes
    prism check-staged              Review all staged git files (pre-commit hook)
    prism scan                      Scan entire repository

REPORT COMMANDS:
    prism reports                   Show review history summary
    prism report <id>               Show a specific report by ID
    prism delete-report <id>        Delete a specific report
    prism clear-reports             Delete ALL reports (asks for confirmation)
    prism dashboard                 Open visual HTML dashboard in browser

AGENT COMMANDS:
    prism agents                   List all available AI agents
    prism agents --enable <name>   Enable a specific agent
    prism agents --disable <name>  Disable a specific agent

SETUP COMMANDS:
    prism init                      Create prism.json config file
    prism install-hook              Install pre-commit git hook

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
    prism check app.py --prompt
    prism check-staged
    prism delete-report 20261108T164053Z
    prism clear-reports --force
    prism agents
    prism dashboard
""")
        return

    if args.command == 'version':
        print("PRISM v2.0.0")
        print("  Architecture: skeleton + import graph + verification + tiered chunking")
        print("  Agents: 6 AI + 4 regex = 10 total")
        print("  Providers: gemini (default), claude, openai")
        return

    if args.command == 'uninstall-hook':
        hook_path = Path('.git/hooks/pre-commit')
        if hook_path.exists():
            hook_path.unlink()
            print("Uninstalled pre-commit hook")
        else:
            print("No pre-commit hook found")
        return

    if args.command == 'stats':
        print("PRISM Review Statistics")
        print("=" * 40)
        print("Use 'prism feedback' for detailed stats.")
        return

    if args.command == 'config':
        config = load_config()
        if getattr(args, 'set', None):
            key, value = args.set
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
            config[key] = value
            with open('prism.json', 'w') as f:
                json.dump(config, f, indent=2)
            print("Set {} = {}".format(key, value))
        elif getattr(args, 'get', None):
            print("{} = {}".format(args.get, config.get(args.get)))
        else:
            print(json.dumps(config, indent=2))
        return

    if args.command == 'test':
        _run_self_tests(getattr(args, 'quick', False))
        return

    if args.command == 'benchmark':
        _run_benchmark(getattr(args, 'file', None), getattr(args, 'iterations', 3))
        return

    if args.command == 'init':
        config = {
            'agents': DEFAULT_AGENTS,
            'block_on': ['critical', 'high'],
            'quality_gates': {
                'max_complexity': 10,
                'max_file_length': 500,
                'min_coverage': 0,
            },
            'confidence_threshold': CONFIDENCE_THRESHOLD,
        }
        with open('prism.json', 'w') as f:
            json.dump(config, f, indent=2)
        print('Created prism.json')
        return

    if args.command == 'install-hook':
        hook_dir = Path('.git/hooks')
        hook_dir.mkdir(parents=True, exist_ok=True)
        hook = hook_dir / 'pre-commit'
        hook.write_text('#!/bin/sh\n# PRISM Pre-Commit Hook\npython -m prism.cli check-staged --prompt --json\n')
        hook.chmod(0o755)
        print('Installed pre-commit hook')
        return

    if args.command == 'policy':
        policy = load_deviation_policy()
        print(json.dumps(policy, indent=2))
        return

    if args.command == 'feedback':
        fb = load_feedback()
        print(json.dumps(fb, indent=2))
        return

    if args.command == 'suppressed':
        print(json.dumps(suppress_summary(), indent=2))
        return

    if args.command == 'reports':
        print(get_report_summary())
        return

    if args.command == 'dashboard':
        viewer = Path(__file__).parent / 'dashboard.html'
        if viewer.exists():
            abs_path = str(viewer.resolve())
            print("Dashboard: file:///{}".format(abs_path.replace("\\", "/")))
            print("Open this in your browser to see the visual report timeline.")
        else:
            print("Dashboard not found at: {}".format(viewer))
        return

    if args.command == 'report':
        report = load_report(args.id)
        if report:
            print(json.dumps(report, indent=2, default=str))
        else:
            print("Report not found: {}".format(args.id))
        return

    if args.command == 'delete-report':
        from prism.reports import delete_report
        success = delete_report(args.id)
        if success:
            print("Report deleted: {}".format(args.id))
        else:
            print("Report not found: {}".format(args.id))
        return

    if args.command == 'clear-reports':
        from prism.reports import clear_reports
        if not args.force:
            confirm = input("Delete ALL reports? (y/N): ").strip().lower()
            if confirm != 'y':
                print("Cancelled.")
                return
        count = clear_reports()
        print("Deleted {} report(s).".format(count))
        return

    if args.command == 'cache':
        if args.action == 'stats':
            stats = get_cache_stats()
            print(json.dumps(stats, indent=2))
        elif args.action == 'clear':
            clear_cache()
            print("Cache cleared.")
        elif args.action == 'status':
            changed, unchanged, cache = get_changed_files()
            print("Changed files: {}".format(len(changed)))
            print("Unchanged files (cached): {}".format(len(unchanged)))
            if changed:
                print("\nChanged:")
                for f in changed[:10]:
                    print("  {}".format(f))
                if len(changed) > 10:
                    print("  ... and {} more".format(len(changed) - 10))
        return

    if args.command == 'check-staged':
        config = load_config()
        files = get_staged_files()
        if not files:
            print('No staged files to review.')
            return

        # --- Test execution (fast-path: changed files only) ---
        # CodeRabbit runs tests and reports real failures. We do the same,
        # but only on changed .py files so it's cheap enough for a hook.
        test_results = None
        if getattr(args, 'test', False):
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
        
        # Separate cached files from files needing review
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
        
        # Review files in parallel (max 5 concurrent to avoid rate limits)
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
        # Save report locally
        commit_hash = ""
        branch = ""
        try:
            commit_hash = subprocess.run(
                ['git', 'rev-parse', 'HEAD'], capture_output=True, text=True
            ).stdout.strip()
            branch = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
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
            # Pure JSON output — no banner, no extra text (for IDE/CI parsing)
            output = _json_output_staged(all_results, config, risk_scores, files, all_findings_list, blocking, test_results)
            print(json.dumps(output, indent=2, default=str))
        else:
            print("")
            print("Report saved: .prism-reports/{}.json".format(report_id))
            
            # Show report interface after review
            print("")
            print("============================================")
            print("  PRISM Review Complete")
            print("============================================")
            print("")
            print("Report ID: {}".format(report_id))
            print("Files reviewed: {}".format(len(files)))
            print("Findings: {}".format(len(all_findings_list)))
            print("")
            print("Next steps:")
            print("  prism reports       # review history")
            print("  prism dashboard     # visual timeline")
            print("  prism feedback      # feedback loop stats")
            
            if getattr(args, 'dashboard', False):
                viewer = Path(__file__).parent / 'dashboard.html'
                if viewer.exists():
                    abs_path = str(viewer.resolve())
                    print("")
                    print("Dashboard: file:///{}".format(abs_path.replace("\\", "/")))
        sys.exit(1 if blocking > 0 else 0)
        return

    if args.command == 'check':
        config = load_config()
        results, score = review_file(args.file, config, args.effort, args.fast)
        # Collect findings for report
        all_findings_list = []
        for r in results:
            for finding in r.findings:
                all_findings_list.append({
                    "agent": finding.agent,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "message": finding.message,
                    "file": finding.file,
                    "line": finding.line,
                    "suggestion": finding.suggestion,
                    "confidence": finding.confidence,
                    "rule_id": finding.rule_id,
                })

        if args.json:
            output = _json_output(results, config, {args.file: score}, args.file)
            print(json.dumps(output, indent=2, default=str))
        else:
            report, blocking = format_report(
                results, config, {args.file: score}
            )
            print(report)
            
            # Interactive prompt for medium/low findings
            if args.prompt and blocking == 0:
                # Skip interactive prompt in CI/CD (no TTY available)
                import sys as _sys
                if not _sys.stdin.isatty():
                    print("(non-interactive mode — skipping prompts)")
                else:
                    all_findings = [f for r in results for f in r.findings]
                    non_blocking = [f for f in all_findings 
                                   if f.severity.value not in ('critical', 'high')]
                    if non_blocking:
                        print("\n" + "="*50)
                        print("Medium/Low findings detected:")
                        print("="*50)
                        for i, f in enumerate(non_blocking):
                            print(f"  [{i+1}] {f.severity.value.upper()} {f.category}")
                            print(f"      Problem: {f.message}")
                            if f.suggestion:
                                print(f"      Suggestion: {f.suggestion}")
                            if f.suggested_code:
                                print(f"      Code fix:")
                                for code_line in f.suggested_code.split("\n"):
                                    print(f"        {code_line}")
                            print(f"      File: {f.file}:{f.line}")
                            print()
                        
                        print("What would you like to do?")
                        print("  a) Apply all auto-fixable changes")
                        print("  s) Skip all (commit as-is)")
                        print("  c) Cancel commit")
                        
                        try:
                            choice = input("Enter your choice (a/s/c): ").strip().lower()
                            if choice == 'a':
                                auto_fixable = get_auto_fixable(non_blocking)
                                if auto_fixable:
                                    path = Path(args.file)
                                    content = path.read_text(errors='ignore')
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
                            elif choice == 'c':
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
                content = path.read_text(errors='ignore')
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
                ['git', 'rev-parse', 'HEAD'], capture_output=True, text=True
            ).stdout.strip()
            branch = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
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
        sys.exit(1 if blocking > 0 else 0)
        return

    parser.print_help()


if __name__ == '__main__':
    main()