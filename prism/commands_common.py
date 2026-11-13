"""Shared helpers for the PRISM commands.

Extracted from cli_commands.py; behaviour unchanged.
"""

import difflib
import json
import os
import shutil
import sys
import subprocess
from pathlib import Path

from prism.agents import AgentResult, Finding, Severity, Blocker, risk_score, quality_gates_met
from prism.autofix import apply_fixes
from prism.cli_config import CONFIDENCE_THRESHOLD, load_deviation_policy, is_deviation
from prism.cli_review import review_file, format_report
from prism.feedback import should_suppress, record_commit
from prism.reports import save_report


def _git_commit_info():
    """Return (commit_hash, branch) for the current repo, or ("", "")."""
    commit_hash, branch = "", ""
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
    return commit_hash, branch


def _agent_table(agents):
    """Normalise the agents config to {name: bool}.

    `prism.json` stores a mapping, but older configs (and DEFAULT_AGENTS) use
    a list of enabled names; both shapes must behave the same.
    """
    if isinstance(agents, dict):
        return agents
    return {name: True for name in agents}


def _set_agent_enabled(agents, name, enabled):
    """Enable/disable one agent in either config shape. Returns True on change."""
    if isinstance(agents, dict):
        if bool(agents.get(name, False)) == enabled:
            return False
        agents[name] = enabled
        return True
    if enabled:
        if name in agents:
            return False
        agents.append(name)
        return True
    if name not in agents:
        return False
    agents.remove(name)
    return True


def _save_config(config):
    with open("prism.json", "w") as f:
        json.dump(config, f, indent=2)


def _apply_fixes_with_preview(path, content, fixes, assume_yes=False,
                              json_mode=False):
    """Show a unified diff, back the file up, then apply the auto-fixes.

    `--fix` used to overwrite the file in place with no preview and no undo,
    so a heuristic rewrite (for example ``eval(x)`` -> ``None``) could change
    behaviour silently. Returns True when the file was written.
    """
    new_content = apply_fixes(fixes, content)
    if new_content == content:
        return False

    diff = "".join(difflib.unified_diff(
        content.splitlines(keepends=True),
        new_content.splitlines(keepends=True),
        fromfile="a/" + path.name, tofile="b/" + path.name, n=2,
    ))
    if not json_mode:
        print("")
        print(diff if diff.endswith("\n") else diff + "\n")

    if not assume_yes:
        if not sys.stdin.isatty():
            print("Non-interactive session: no changes written (use --yes).")
            return False
        answer = input("Apply these {} fix(es)? [y/N] ".format(
            len(fixes))).strip().lower()
        if answer not in ("y", "yes"):
            print("No changes written.")
            return False

    backup = path.with_name(path.name + ".prism-bak")
    shutil.copy2(str(path), str(backup))
    path.write_text(new_content)
    if not json_mode:
        print("Backup saved: {}".format(backup))
    return True


def _cached_risk_score(file_path, cached_findings):
    """Recompute the risk score for a file served from the cache.

    Cached findings are stored as dicts; risk_score needs Finding objects,
    so they are rebuilt exactly like the blocking path does.
    """
    try:
        content = Path(file_path).read_text(errors="ignore")
    except OSError:
        content = ""
    findings = [f for r in _findings_to_agent_results(cached_findings)
                for f in r.findings]
    return risk_score(file_path, content, content, findings)


def _findings_to_agent_results(cached_findings):
    """Rebuild AgentResult objects from cached finding dicts.

    Cached findings used to be appended to the report payload but not to the
    results used for blocking/JSON, so a previously reviewed secret stopped
    blocking on the next commit.
    """
    grouped = {}
    for item in cached_findings:
        sev = str(item.get("severity", "low"))
        try:
            severity = Severity(sev)
        except ValueError:
            severity = Severity.LOW
        f = Finding(
            agent=item.get("agent", "cache"),
            severity=severity,
            category=item.get("category", ""),
            message=item.get("problem", ""),
            file=item.get("file", ""),
            line=item.get("line"),
            suggestion=item.get("suggestion"),
            suggested_code=item.get("suggested_code"),
            blocker=Blocker.BLOCKS if sev in ("critical", "high") else Blocker.WARNS,
            confidence=item.get("confidence", 0.85),
            rule_id=item.get("rule_id"),
        )
        grouped.setdefault(f.agent, []).append(f)
    results = []
    for name, findings in grouped.items():
        results.append(AgentResult(
            agent_name=name,
            findings=findings,
            passed=not any(x.blocker == Blocker.BLOCKS for x in findings),
        ))
    return results


def _empty_staged_output(files, skipped=None):
    output = {
        "files_reviewed": files,
        "risk_scores": {},
        "total_findings": 0,
        "blocking": 0,
        "quality_gates_passed": True,
        "commit_allowed": True,
        "findings": [],
    }
    if skipped:
        output["skipped_ignored"] = skipped
    return output


def _finalize_review(all_results, all_findings_list, risk_scores, files,
                     config, json_mode, test_results=None, args=None):
    report_text, blocking = format_report(all_results, config, risk_scores)
    if not json_mode:
        print(report_text)

    gates_ok = quality_gates_met(all_results, config)
    if test_results is not None and not test_results.get("ok", True):
        gates_ok = False
    allowed = blocking == 0 and gates_ok

    commit_hash, branch = _git_commit_info()
    report_id = save_report(
        files_reviewed=files,
        findings=all_findings_list,
        risk_score=sum(risk_scores.values()) / max(len(risk_scores), 1),
        blocking=blocking,
        commit_allowed=allowed,
        commit_hash=commit_hash,
        branch=branch,
    )
    record_commit(all_findings_list, commit_hash)

    if json_mode:
        output = _json_output_staged(all_results, config, risk_scores, files,
                                     all_findings_list, blocking, test_results)
        print(json.dumps(output, indent=2, default=str))
        sys.exit(0 if output["commit_allowed"] else 1)

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

    # Every review leaves a browsable report, so the dashboard is generated
    # unconditionally and opened in the default browser unless the developer
    # opted out (PRISM_NO_DASHBOARD, --no-dashboard, or CI/JSON mode).
    if not json_mode and _dashboard_enabled(args):
        from prism.commands_reports import build_dashboard
        build_dashboard(open_browser=True)

    sys.exit(0 if allowed else 1)


def _dashboard_enabled(args):
    """True when the dashboard should open after a review.

    Skipped for automated environments (no display, no point opening a
    browser) and whenever the developer explicitly opts out.
    """
    if getattr(args, "no_dashboard", False):
        return False
    if os.getenv("PRISM_NO_DASHBOARD"):
        return False
    if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


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
