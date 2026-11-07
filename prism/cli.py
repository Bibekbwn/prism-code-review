import argparse
import json
import os
import sys
import subprocess
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
from prism.agents_security import SecurityAgent
from prism.agents_quality import QualityAgent
from prism.agents_policy import PolicyAgent
from prism.agents_test import TestAgent
from prism.agents_ai import AIReviewerAgent
from prism.feedback import load_feedback, should_suppress, suppress_summary, scan_dependencies
from prism.autofix import generate_fix, apply_fixes, get_auto_fixable
from prism.logging_config import logger
from prism.reports import save_report, get_recent_reports, get_report_summary, load_report
from prism.codebase_cache import (
    get_changed_files, get_cached_findings, cache_findings,
    clear_cache, get_cache_stats,
)

DEFAULT_AGENTS = ['security', 'quality', 'policy', 'test', 'ai_reviewer']
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


def review_file(file_path, config, effort='balanced'):
    path = Path(file_path)
    if not path.exists():
        return [], 0.0
    content = path.read_text(errors='ignore')
    agents = list(config.get('agents', DEFAULT_AGENTS))
    results = run_pipeline(agents, file_path, content, content)

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


def main():
    parser = argparse.ArgumentParser(prog='prism', description='PRISM - Pre-Commit Code Review')
    parser.add_argument('--effort', choices=['lite', 'balanced', 'max'],
                        default='balanced', help='AI review effort level')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('agents', help='List available agents')

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

    sub.add_parser('check-staged', help='Review staged git changes')
    sub.add_parser('init', help='Create prism.json config')
    sub.add_parser('install-hook', help='Install pre-commit hook')
    sub.add_parser('policy', help='Show deviation policy')
    sub.add_parser('feedback', help='Show feedback loop stats')
    sub.add_parser('suppressed', help='Show historically suppressed rules')
    sub.add_parser('reports', help='Show review history')
    sub.add_parser('report', help='Show a specific report by ID').add_argument('id')
    sub.add_parser('dashboard', help='Open visual report dashboard in browser')
    cache_cmd = sub.add_parser('cache', help='Manage codebase analysis cache')
    cache_cmd.add_argument('action', choices=['stats', 'clear', 'status'],
                           help='Cache action to perform')

    args = parser.parse_args()

    if args.command == 'agents':
        for name, agent in AGENT_REGISTRY.items():
            print("  {}: {}".format(name, agent.description))
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
        hook.write_text('#!/bin/sh\npython -m prism.cli check-staged --effort balanced\n')
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
        viewer = Path(__file__).parent / 'report_viewer.html'
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
        all_results = []
        risk_scores = {}
        all_findings_list = []
        
        # Use codebase cache to avoid re-scanning unchanged files
        try:
            changed, unchanged, cache = get_changed_files()
        except Exception:
            changed, unchanged, cache = files, [], {}
        
        for f in files:
            # Check if we have cached findings for this file
            cached = get_cached_findings(f, cache)
            if cached and f in unchanged:
                # Reuse cached findings
                for cf in cached:
                    all_findings_list.append(cf)
                print("  [cached] {}".format(f))
                continue
            
            results, score = review_file(f, config, args.effort)
            all_results.extend(results)
            risk_scores[f] = score
            file_findings = []
            for r in results:
                for finding in r.findings:
                    finding_dict = {
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
                    }
                    all_findings_list.append(finding_dict)
                    file_findings.append(finding_dict)
            # Cache the findings
            cache_findings(f, file_findings, cache)
            print("  [scanned] {}".format(f))
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
        if not args.json:
            print("")
            print("Report saved: .prism-reports/{}.json".format(report_id))
        sys.exit(1 if blocking > 0 else 0)
        return

    if args.command == 'check':
        config = load_config()
        results, score = review_file(args.file, config, args.effort)

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
                            sys.exit(1)
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