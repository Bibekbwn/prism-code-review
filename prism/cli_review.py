import re
from pathlib import Path

from prism.agents import (
    AGENT_REGISTRY, Finding, Severity, Blocker, AgentResult, run_pipeline,
    risk_score, quality_gates_met,
)
from prism.ai_common import build_skeleton
from prism.feedback import scan_dependencies, should_suppress
from prism.modes import get_mode, select_agents
from prism import agents_policy, agents_quality

from prism.cli_config import (
    CONFIDENCE_THRESHOLD, load_deviation_policy, is_deviation, enabled_agents,
)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "into", "when",
    "use", "using", "used", "has", "have", "are", "was", "were", "not",
    "but", "can", "could", "should", "would", "will", "may", "might",
    "there", "their", "them", "then", "than", "also", "only", "very",
    "which", "while", "because", "been", "being", "does", "did", "each",
}

_CATEGORY_FAMILY = (
    ("secret", ("secret", "credential", "password", "token", "api key", "apikey")),
    ("injection", ("injection", "command", "eval", "exec", "deserial", "xss", "sql")),
    ("auth", ("auth", "permission", "access control", "authorization")),
    ("performance", ("performance", "n+1", "memory", "algorithm", "latency", "throughput")),
    ("architecture", ("architect", "coupling", "modular", "layer", "god", "design")),
    ("test", ("test", "coverage", "assert")),
    ("quality", ("complex", "duplicat", "maintain", "style", "docstring",
                 "naming", "unused", "readab")),
)


def _category_family(category):
    lowered = (category or "").lower()
    for family, needles in _CATEGORY_FAMILY:
        if any(n in lowered for n in needles):
            return family
    return lowered


def _message_tokens(message):
    words = re.findall(r"[a-z0-9_]{3,}", (message or "").lower())
    return {w for w in words if w not in _STOPWORDS}


# Tokens that name *which* secret is exposed. Two findings about different
# subjects on the same line (an AWS key and a DB password) are distinct issues
# and must not be collapsed into one.
_SECRET_SUBJECTS = ("secret", "credential", "password", "passwd", "pwd",
                    "token", "key")

# Qualifier tokens distinguish two findings with the same subject: an AWS key
# and an SSH key on the same line are two different secrets. Generic qualifiers
# (api/access/private/public) describe the *kind* of key, not a provider, so
# they are treated as wildcards.
_SECRET_QUALIFIERS = (
    "aws", "amazon", "gcp", "google", "azure", "ssh", "db", "database",
    "postgres", "postgresql", "mysql", "mongo", "mongodb", "redis", "stripe",
    "github", "gitlab", "slack", "jwt", "smtp", "ftp", "s3",
)
_GENERIC_QUALIFIERS = ("api", "access", "private", "public", "root", "admin")


def _secret_subjects(tokens):
    return {t for t in tokens if t in _SECRET_SUBJECTS}


def _secret_qualifiers(tokens):
    return {t for t in tokens if t in _SECRET_QUALIFIERS}


def _same_secret(a_tokens, b_tokens):
    """True when two messages describe the same secret, not two secrets."""
    sa, sb = _secret_subjects(a_tokens), _secret_subjects(b_tokens)
    if sa != sb:
        return False
    qa, qb = _secret_qualifiers(a_tokens), _secret_qualifiers(b_tokens)
    if not qa or not qb or qa == qb or (qa | qb) & set(_GENERIC_QUALIFIERS):
        return True
    return bool(qa & qb)


def _similar_finding(a, f):
    """True when two AI findings describe the same issue on the same line.

    Sharing a category family is not enough on its own: a line can carry a
    hardcoded API key *and* a hardcoded DB password. Collapse only when the
    messages overlap textually, or when the same category family is backed by
    the same secret subject.
    """
    ta, tf = _message_tokens(a.message), _message_tokens(f.message)
    overlap = (len(ta & tf) / len(ta | tf)) if (ta and tf) else 0.0
    if overlap >= 0.6:
        return True
    if _category_family(a.category) != _category_family(f.category):
        return False

    if _secret_subjects(ta) or _secret_subjects(tf):
        return _same_secret(ta, tf)
    if not ta or not tf:
        return True
    return overlap >= 0.34


def _rank(f):
    return (_SEVERITY_RANK.get(f.severity.value, 0), f.confidence)


def dedupe_results(results):
    """Remove duplicate AI findings without merging distinct same-line issues.

    AI agents describe the same issue with different categories and wording,
    so collapse per (file, line) *within a category family* or when the
    messages are textually similar. Findings in different families (for
    example a hardcoded secret and an O(n^2) loop on the same line) are kept.
    """
    ai_kept = []
    for r in results:
        kept = []
        for f in r.findings:
            if not f.agent.startswith("ai_"):
                kept.append(f)
                continue

            duplicate = next(
                (k for k in ai_kept
                 if k.file == f.file and k.line == f.line
                 and _similar_finding(k, f)),
                None,
            )
            if duplicate is None:
                ai_kept.append(f)
                kept.append(f)
            elif _rank(f) > _rank(duplicate):
                for other in results:
                    if duplicate in other.findings:
                        other.findings.remove(duplicate)
                ai_kept.remove(duplicate)
                ai_kept.append(f)
                kept.append(f)
        r.findings = kept

    return [r for r in results if r.findings or not r.agent_name.startswith("ai_")]


def review_file(file_path, config, effort="balanced", fast=False, diff=""):
    """Review a single file with the configured agents.

    Returns (results, risk_score). `diff` (git diff hunks) is preferred over
    full content when available. `--effort lite` runs only deterministic
    regex agents (no API calls); `balanced`/`max` also run the AI agents.

    The stored ``mode`` (``prism mode``) caps the selection: ``regex`` pins the
    review to the deterministic agents and ``none`` skips agents entirely.
    """
    path = Path(file_path)
    if not path.exists():
        return [], 0.0
    content = path.read_text(errors="ignore")
    # Binary files are not source; scanning them as text produced magic-number
    # false positives (e.g. .bin, images, compiled artifacts).
    if "\x00" in content:
        return [], 0.0
    skeleton = build_skeleton(file_path, content)
    line_count = content.count("\n") + 1
    agents = enabled_agents(config)
    # `lite` effort is for IDE/LSP use: deterministic agents only, no API calls
    # and no repo-wide coverage run.
    if effort == "lite":
        fast = True
    agents = select_agents(agents, get_mode(config), effort)
    # The policy agent's noisy rules (SPDX headers, print(), TODO refs) are
    # opt-in per project rather than always on.
    policy_cfg = config.get("policy", {}) or {}
    agents_policy.HEADER_CHECKS_ENABLED = bool(policy_cfg.get("headers", False))
    agents_policy.BANNED_CONSOLE_ENABLED = bool(
        policy_cfg.get("banned_console", False))
    agents_policy.CHECK_PRINT_ENABLED = bool(policy_cfg.get("check_print", False))
    agents_policy.CHECK_TODO_REFS_ENABLED = bool(
        policy_cfg.get("check_todo_refs", False))
    if "policy" in AGENT_REGISTRY:
        AGENT_REGISTRY["policy"]._policy = policy_cfg
    # Quality rules that are style preferences are off unless opted in.
    if "quality" in AGENT_REGISTRY:
        AGENT_REGISTRY["quality"]._enabled = dict(
            agents_quality.QUALITY_DEFAULTS,
            **(config.get("quality", {}) or {}))
    if not agents:
        # `none` mode: nothing to review, but callers still expect a result set
        # so the report/JSON/dashboard paths keep working.
        return [], 0.0
    results = run_pipeline(agents, file_path, content, diff, skeleton,
                           line_count=line_count, fast=fast)

    # Run SCA dependency scan (a deterministic check, so `none` mode skips it)
    sca_findings = [] if not agents else scan_dependencies(file_path, content)
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

    results = dedupe_results(results)
    findings = [f for r in results for f in r.findings]
    score = risk_score(file_path, content, content, findings)
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

    blocking = sum(1 for f in all_findings if f["blocking"])
    gates_ok = quality_gates_met(results, config)

    return {
        "file": file_path,
        "risk_score": risk_scores.get(file_path, 0.0),
        "total_findings": len(all_findings),
        "findings": all_findings,
        "blocking": blocking,
        "quality_gates_passed": gates_ok,
        "commit_allowed": blocking == 0 and gates_ok,
    }
