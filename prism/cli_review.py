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
from prism import agents_security, agents_test

# The regex agents must be registered for any review path (CLI, LSP, library).
_REGEX_AGENT_MODULES = (agents_security, agents_test)

# Importing the AI agent modules runs their @register_agent decorators. Without
# this, the default agent list referenced ai_* names that were never in the
# registry, so run_pipeline logged "Agent not found" and skipped every AI
# review. The tuple keeps the imports referenced for linters.
from prism import (ai_security, ai_quality, ai_policy, ai_test,
                   ai_architecture, ai_performance)

_AI_AGENT_MODULES = (ai_security, ai_quality, ai_policy, ai_test,
                     ai_architecture, ai_performance)

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

# "credential" is what any secret is called. A rule prints it when it will not
# say which secret it matched, so it corroborates a finding rather than naming a
# second secret.
_UNNAMED_SECRET_NOUNS = frozenset({"credential"})


def _secret_subjects(tokens):
    return {t for t in tokens if t in _SECRET_SUBJECTS}


def _secret_qualifiers(tokens):
    return {t for t in tokens if t in _SECRET_QUALIFIERS}


def _views(finding):
    """The two views of a finding's subject: its message and its category.

    Both are needed. A category can be a bare rule name that names nothing
    ("Banned Pattern"), and a message can leave out the family (a rule that
    says only "command injection").
    """
    return (_message_tokens(finding.message),
            _message_tokens(finding.category))


def _all_tokens(finding):
    """Every word of a finding: its message and its category."""
    message_tokens, category_tokens = _views(finding)
    return message_tokens | category_tokens


def _kind_tokens(finding):
    """The kinds of problem this finding describes, read off its message.

    The message is where the kind lives. A category is only a label, and for
    the deterministic agents it is a *rule* name -- "Secret Exposure",
    "Dangerous Pattern", "Banned Pattern" -- chosen from a closed set that
    does not line up across agents: one rule files a hardcoded credential under
    "Banned Pattern" and another under "Secret Exposure". Reading the kind off
    the category would call those two findings different kinds of problem and
    keep one secret reported twice.
    """
    message_tokens, _category_tokens = _views(finding)
    kinds = {family for family, needles in _CATEGORY_FAMILY
             if any(n in message_tokens for n in needles)}
    if kinds:
        return kinds
    # The message names no kind ("Hardcoded credential in source"), so the
    # category is the only evidence left, and a bare rule name is weak: it is
    # an assertion that this is *a* finding, not what kind.
    return set()


def _about_secret(finding):
    """True when this finding is about a hardcoded secret.

    Read off the nouns the finding actually names, so an inflected or reworded
    one still counts: "Hardcoded API key detected" and "credential leakage" both
    name a secret, where an exact word match only caught the singular
    "credential" and the closed-up "apikey". Missing that, the copies the model
    agents write for one secret were kept as separate findings.
    """
    return bool(_secret_subjects(_message_tokens(finding.message))
                or _secret_subjects(_message_tokens(finding.category)))


def _subject_of(finding):
    """The words naming *which* issue this is, not what kind.

    Family words are dropped ("secret", "performance" say what kind of problem
    it is and every finding of that kind carries them), and so are the secret
    nouns and qualifiers, which ``_same_secret`` compares separately.
    """
    tokens = _all_tokens(finding)
    for _family, needles in _CATEGORY_FAMILY:
        tokens -= set(needles)
    return tokens - set(_SECRET_SUBJECTS) - set(_SECRET_QUALIFIERS)


def _same_secret(a, f):
    """True when two findings are about the same secret, not two secrets.

    A secret is named by its nouns ("key", "password", "token") and, when the
    finding is precise about it, by a qualifier ("aws", "ssh", "db").

    The nouns are a claim about which secret this is. Two findings make the same
    claim when they name the same set of nouns, and that is what lets them
    collapse: "Possible api key detected" and "Hardcoded api key in source" are
    the same finding, while "Possible api key detected" and "Possible auth token
    detected" are two, and so are "Hardcoded secret found" and "Hardcoded
    password found", where one names only the family and the other names a kind
    of secret.

    "credential" is the one noun that claims nothing: a rule prints it when it
    will not say which secret it matched, so it is set aside on both sides. A
    side left with no nouns is making no claim, and a claim with no claim is not
    a contradiction -- "Possible api key detected" and "Banned Pattern: hardcoded
    credential" are one hardcoded key.

    When both sides name a qualifier, the qualifier decides: an AWS key and an
    SSH key are both keys, and only the qualifier says which.

    The nouns are read off the message alone. A category is a label from a
    closed set, and the set files every secret under names that contain "secret"
    ("Secret Exposure"), so it would add the same family word to both sides and
    hide the difference between the two findings being compared.
    """
    nouns_a = _secret_subjects(_message_tokens(a.message)) - _UNNAMED_SECRET_NOUNS
    nouns_b = _secret_subjects(_message_tokens(f.message)) - _UNNAMED_SECRET_NOUNS

    # One side names no particular secret: it is agreeing that a secret is there,
    # which is not a second secret. When both name one, the claims have to be
    # compatible -- the same noun, or one naming a superset of the other ("api
    # key" against "api key or secret string"), never two disjoint nouns.
    if nouns_a and nouns_b and not (nouns_a <= nouns_b or nouns_b <= nouns_a):
        return False

    qa = _secret_qualifiers(_message_tokens(a.message))
    qb = _secret_qualifiers(_message_tokens(f.message))
    if qa and qb:
        return bool(qa & qb)
    return True


def _kind_conflicts(a, f):
    """True when both findings describe a kind of problem, and disjoint kinds.

    Two findings that both say what kind of problem they are, and say different
    ones, are different problems sharing a line: a secret and an O(n^2) loop.

    Kinds come from the message only (``_kind_tokens``). A category is a label
    an agent picked from a closed set of rule names, and for the deterministic
    agents those names describe rules rather than problems, so they cannot
    support a claim that two findings are unrelated.
    """
    ka, kf = _kind_tokens(a), _kind_tokens(f)
    return bool(ka and kf and not (ka & kf))


def _same_issue(a, f):
    """True when two findings on the same line describe the same issue.

    Every agent answers the same question, so one problem arrives several times
    and the copies must collapse, or the review lists one secret three times and
    the blocking count is fiction.

    Two findings are one issue when their kinds do not conflict and their
    subjects agree. The kind check is what keeps a secret from collapsing into
    the O(n^2) loop beside it on the same line; within that, secrets compare by
    noun and qualifier, and everything else by subject-word overlap.
    """
    if _kind_conflicts(a, f):
        return False

    if _about_secret(a) and _about_secret(f):
        return _same_secret(a, f)

    ma, mf = _message_tokens(a.message), _message_tokens(f.message)
    # Identical messages are one finding reported twice, however the two agents
    # labelled it: a TODO marker is "Incomplete Code" to one and "Invalid Issue
    # Reference" to the other.
    if ma and ma == mf:
        return True

    sa, sb = _subject_of(a), _subject_of(f)
    if not sa or not sb:
        return True

    overlap = len(sa & sb) / len(sa | sb)
    if overlap >= 0.6:
        return True
    if sa <= sb or sb <= sa:
        return True
    # The same kind of problem, and at least one subject word in common. Two
    # agents describe one defect in different words -- "shell command" against
    # "os/exec using unsanitized user input" -- and the shared noun is the thing
    # they are both pointing at. The kind check keeps a command injection from
    # collapsing into the SQL injection beside it.
    ka, kf = _kind_tokens(a), _kind_tokens(f)
    return bool(ka and ka == kf and (sa & sb))


def _rank(f):
    """Sort key for "which copy of a finding is worth keeping"."""
    return (_SEVERITY_RANK.get(f.severity.value, 0), f.confidence)


def dedupe_results(results):
    """Collapse findings that describe one issue reported more than once.

    Every agent answers the same question, so the same problem arrives several
    times: two regex agents both flag the same hardcoded key, and an AI agent
    then describes it again in its own words. The review listed each copy as a
    separate finding, which inflated counts and buried the report.

    Collapse happens per (file, line), and the surviving copy records who else
    raised it (``corroborated_by``). Findings on different lines, or on the
    same line about genuinely different issues (a secret *and* an O(n^2) loop),
    are kept: that is disagreement between agents, not duplication.
    """
    # (file, line) -> the finding kept as the representative for that location,
    # and the list holding it. The list is needed because the representative can
    # be replaced later by a stronger copy from another agent's result.
    kept_by_spot = {}
    for r in results:
        kept = []
        for f in r.findings:
            spot = (f.file, f.line)
            found = kept_by_spot.get(spot)
            if found is None or not _same_issue(found[0], f):
                kept_by_spot[spot] = (f, kept)
                kept.append(f)
                continue

            duplicate, owner = found
            if f.agent == duplicate.agent:
                # The same agent raised the same issue twice: one copy, and no
                # agent credits itself.
                continue

            if _rank(f) > _rank(duplicate):
                # The stronger copy wins, wherever it came from: it replaces the
                # weaker one in the result that was holding it.
                f.corroborated_by = [duplicate.agent] + [
                    a for a in duplicate.corroborated_by if a != f.agent
                ]
                if owner is kept:
                    _replace_in_place(kept, duplicate, f)
                else:
                    owner[:] = [x for x in owner if x is not duplicate]
                    kept.append(f)
                kept_by_spot[spot] = (f, kept)
            elif f.agent not in duplicate.corroborated_by:
                duplicate.corroborated_by.append(f.agent)
        r.findings = kept

    # A result left with nothing is a duplicate-only result: dropping it keeps
    # the "who said what" structure honest (only corroborating agents appear in
    # corroborated_by). Deterministic results are never dropped -- they are the
    # record that the agent ran and found nothing, which is what the report and
    # the enable/disable contract depend on.
    return [r for r in results
            if r.findings or not r.agent_name.startswith("ai_")]


def _replace_in_place(items, old, new):
    """Swap one finding for another in a list, by identity.

    ``Finding`` compares by value, so ``list.index`` would match a different
    finding that happens to hold the same values.
    """
    for i, x in enumerate(items):
        if x is old:
            items[i] = new
            return True
    return False


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


def format_report(results, config, risk_scores=None, audit=False):
    """Format review results as a human-readable report string.

    ``audit`` is set by ``scan``: the same findings are reported, but the
    verdict is advisory ("no commit gate") because a whole-project audit is
    not a pre-commit check.
    """
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
            if f.corroborated_by:
                lines.append("         Also reported by: {}".format(
                    ", ".join(f.corroborated_by)))
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
        if audit:
            lines.append(
                "AUDIT: {} issue(s) found - review-only, no commit gate.".format(
                    blocking_count))
        else:
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
