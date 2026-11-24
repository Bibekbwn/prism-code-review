"""Parse LLM JSON into Finding objects and verify them before delivery.

Verification catches hallucinated line numbers, invalid suggested code,
duplicates, and findings whose message references code not at the claimed
line. Categories with a deterministic regex equivalent also get a
cross-check (the CodeRabbit "verification agent" pattern).
"""

import re
import hashlib
import logging

from prism.langs import lang_for

logger = logging.getLogger(__name__)

_CROSS_CHECK_CATEGORIES = {
    "Secret Exposure",
    "Dangerous Pattern",
    "Duplication",
    "File Length",
    "Todo",
    "Naming Convention",
}

_AGENT_PREFIX = {
    "ai_security": "SECU",
    "ai_quality": "QUAL",
    "ai_policy": "POL",
    "ai_test": "TST",
    "ai_architecture": "ARC",
    "ai_performance": "PERF",
}


def _is_python(file_path):
    """True when a suggested fix for ``file_path`` must parse as Python."""
    spec = lang_for(file_path)
    return spec is None or spec.name == "python"


def _finding_id(prefix, item, file_path):
    """Deterministic per-instance ID derived from the finding's content.

    Using a content hash instead of a sequence number guarantees uniqueness
    across calls — chunked reviews call parse_findings once per chunk, so a
    sequence counter would restart and emit duplicate SECU-AI-001 IDs. The
    hash is stable across runs, so the same finding gets the same ID.
    """
    raw = "{}|{}|{}|{}".format(
        file_path,
        item.get("line"),
        item.get("message", ""),
        item.get("category", ""),
    )
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:4]
    return "{}-AI-{}".format(prefix, digest)


def parse_findings(result, file_path, agent_name):
    """Parse LLM JSON response into Finding objects with unique rule IDs."""
    from prism.agents import Finding, Severity, Blocker

    prefix = _AGENT_PREFIX.get(agent_name, agent_name.upper()[:4])
    findings = []
    for item in result.get("findings", []):
        try:
            line_val = item.get("line")
            if line_val is not None:
                try:
                    line_val = int(line_val)
                except (ValueError, TypeError):
                    line_val = None

            sev_str = str(item.get("severity", "low")).lower()
            confidence = item.get("confidence", 0.85)
            try:
                confidence = float(confidence)
            except (ValueError, TypeError):
                confidence = 0.85

            findings.append(Finding(
                agent=agent_name,
                severity=Severity(sev_str),
                category=item.get("category", agent_name),
                message=item.get("message", ""),
                file=item.get("file", file_path),
                line=line_val,
                suggestion=item.get("suggestion"),
                suggested_code=item.get("suggested_code"),
                blocker=Blocker.BLOCKS if sev_str in ("critical", "high") else Blocker.WARNS,
                confidence=confidence,
                rule_id=_finding_id(prefix, item, file_path),
            ))
        except Exception as exc:
            logger.warning("Finding parse error: %s", exc)
    return findings


_PREPROCESSOR = re.compile(
    r"^\s*#\s*(define|include|if|ifdef|ifndef|elif|else|endif|undef|pragma|error|line)\b")


def _is_comment_or_blank(text):
    """True when a line carries no statement a finding could point at.

    A model often reports the comment that introduces a defect instead of the
    statement that has it, which leaves one secret reported twice: once by the
    rule at the assignment, once by the model one line above.

    ``#define`` is a statement, not a comment, so a preprocessor line is left
    alone; treating it as a comment would move a finding off the line that
    actually holds the secret.
    """
    stripped = (text or "").strip()
    if not stripped:
        return True
    if _PREPROCESSOR.match(stripped):
        return False
    return stripped.startswith(("#", "//", "/*", "*", "*/", "--"))


def _snap_to_code(line, lines, max_line):
    """Move a line that points at a comment or blank line down to the code.

    Returns the original line when there is no code below it, so a file that is
    entirely comments keeps its finding where the model put it.
    """
    if line is None or line < 1 or line > max_line:
        return line
    if not _is_comment_or_blank(lines[line - 1]):
        return line
    for candidate in range(line + 1, max_line + 1):
        if not _is_comment_or_blank(lines[candidate - 1]):
            return candidate
    return line


def verify_findings(findings, file_path, content):
    """Validate AI-generated findings before they reach the user."""
    if not findings:
        return []

    lines = content.split("\n")
    max_line = len(lines)
    verified, seen = [], set()

    for f in findings:
        if f.line is not None and (f.line < 1 or f.line > max_line):
            logger.warning("Dropped: line %s out of bounds (%d lines)", f.line, max_line)
            continue
        if f.line is not None:
            f.line = _snap_to_code(f.line, lines, max_line)
        if not file_path or '\x00' in file_path:
            logger.warning("Dropped: invalid file path '%s'", file_path)
            continue

        key = (f.agent, f.line, f.message.strip().lower()[:100])
        if key in seen:
            logger.warning("Dropped duplicate: %s", f.message[:80])
            continue
        seen.add(key)

        if f.suggested_code and _is_python(f.file):
            # Only a Python fix can be parsed here. Rejecting a Go or Rust
            # snippet for not being valid Python would discard a correct finding
            # along with the suggestion attached to it.
            try:
                import ast
                ast.parse(f.suggested_code)
            except SyntaxError:
                logger.warning("Dropped: invalid suggested_code: %s", f.suggested_code[:80])
                continue

        if f.line is not None and f.line <= max_line:
            nearby = "\n".join(lines[max(0, f.line - 3):f.line + 3])
            code_words = {
                w for w in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', f.message)
                if '_' in w or re.match(r'^[a-z]+[A-Z]', w)
            }
            if code_words and not any(w.lower() in nearby.lower() for w in code_words):
                logger.warning("Dropped: message references code not at line %s", f.line)
                continue

        if f.category in _CROSS_CHECK_CATEGORIES:
            confirmed, reason = _cross_check(f, lines)
            if not confirmed:
                f.confidence = max(0.1, f.confidence * 0.5)
                logger.info("Verification: no deterministic support (%s) — confidence %.2f",
                            reason, f.confidence)

        verified.append(f)

    logger.info("Verification: %d/%d findings passed", len(verified), len(findings))
    return verified


def _cross_check(finding, lines):
    """Cross-check an AI finding against deterministic regex patterns."""
    line_no = finding.line
    if line_no is None or line_no < 1 or line_no > len(lines):
        return False, "no line to check"
    line_text = lines[line_no - 1]

    if finding.category in ("Secret Exposure", "Dangerous Pattern"):
        try:
            from prism.agents_security import SECRET_PATTERNS, DANGEROUS_PATTERNS
        except Exception:
            return False, "security patterns unavailable"
        for pattern, _label, _rule_id in SECRET_PATTERNS + DANGEROUS_PATTERNS:
            if re.search(pattern, line_text, re.IGNORECASE):
                return True, "regex pattern matches at claimed line"

    if finding.category == "File Length" and len(line_text) > 120:
        return True, "line exceeds 120 chars"
    if finding.category == "Todo" and re.search(r'TODO|FIXME|XXX', line_text):
        return True, "TODO marker found"
    if finding.category == "Naming Convention" and finding.file and finding.file.endswith(".py"):
        if re.search(r'\b[a-z]+[A-Z]\w*\s*=', line_text):
            return True, "camelCase variable found"

    return False, "no deterministic pattern supports this finding"