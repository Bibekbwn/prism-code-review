import json
from pathlib import Path

from prism.agents import (
    Finding, Severity, Blocker, AgentResult, run_pipeline, risk_score,
    quality_gates_met,
)
from prism.ai_common import build_skeleton
from prism.feedback import scan_dependencies, should_suppress
from prism.logging_config import logger

from prism.cli_config import (
    DEFAULT_AGENTS, CONFIDENCE_THRESHOLD, load_deviation_policy, is_deviation,
)


def review_file(file_path, config, effort="balanced", fast=False, diff=""):
    """Review a single file with the configured agents.

    Returns (results, risk_score). `diff` (git diff hunks) is preferred over
    full content when available. `--effort lite` runs only deterministic
    regex agents (no API calls); `balanced`/`max` also run the AI agents.
    """
    path = Path(file_path)
    if not path.exists():
        return [], 0.0
    content = path.read_text(errors="ignore")
    skeleton = build_skeleton(file_path, content)
    line_count = content.count("\n") + 1
    agents = list(config.get("agents", DEFAULT_AGENTS))
    # `lite` effort is for IDE/LSP use: deterministic agents only, no API calls.
    if effort == "lite":
        agents = [a for a in agents if not a.startswith("ai_")]
    results = run_pipeline(agents, file_path, content, diff, skeleton,
                           line_count=line_count, fast=fast)

    # Run SCA dependency scan
    sca_findings = scan_dependencies(file_path, content)
    if sca_findings:
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
            results.append(AgentResult(
                agent_name="sca",
                findings=sca_results,
                passed=not any(f.blocker == Blocker.BLOCKS for f in sca_results),
                duration_ms=0.0,
            ))

    score = risk_score(file_path, content, content)
    return results, score


def format_report(results, config, risk_scores=None):
    """Format review results as a human-readable report string."""
    lines = []
    blocking_sev = set(config.get("block_on", ["critical", "high"]))
    conf_threshold = config.get("confidence_threshold", CONFIDENCE_THRESHOLD)
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
            tag = "BLOCK" if is_blocking else "WARN"
            lines.append("    [{}] {} {} [{}] conf={:.0f}%".format(
                tag, f.severity.value.upper(), f.category,
                f.rule_id or "N/A", f.confidence * 100))
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
            bar = "#" * int(score * 20) + "-" * (20 - int(score * 20))
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

    return "\n".join(lines), blocking_count


def json_output(results, config, risk_scores, file_path):
    """Generate JSON output for IDE/CI integration."""
    blocking_sev = set(config.get("block_on", ["critical", "high"]))
    conf_threshold = config.get("confidence_threshold", CONFIDENCE_THRESHOLD)
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

    return {
        "file": file_path,
        "risk_score": risk_scores.get(file_path, 0.0),
        "total_findings": len(all_findings),
        "findings": all_findings,
        "blocking": sum(1 for f in all_findings if f["blocking"]),
        "commit_allowed": sum(1 for f in all_findings if f["blocking"]) == 0,
    }
