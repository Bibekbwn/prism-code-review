"""
Auto-fix engine - Generates corrected code for auto-fixable findings.

Based on GitHub Copilot's "suggested changes" and CodeRabbit's "One-Click Fix":
- AI generates corrected code snippets
- Developer reviews before applying
- Changes are attributed to the developer, not committed automatically
"""

import re
from typing import List, Optional, Tuple
from prism.agents import Finding
from prism.logging_config import logger


def _is_valid_python(source: str) -> bool:
    """True when source parses as a complete Python module."""
    try:
        compile(source, "<prism-autofix>", "exec")
    except (SyntaxError, ValueError):
        return False
    return True


def generate_fix(finding: Finding, original_content: str) -> Optional[str]:
    """
    Generate a corrected version of the line(s) for a finding.

    Returns the fixed code string, or None if no fix is possible.
    """
    lines = original_content.split("\n")
    line_idx = (finding.line or 1) - 1

    if line_idx < 0 or line_idx >= len(lines):
        return None

    original_line = lines[line_idx]
    fix_type = _classify_fix(finding)

    if fix_type == "remove_line":
        return _remove_line(lines, line_idx)

    if fix_type == "replace_secret":
        return _replace_secret(original_line, finding)

    if fix_type == "remove_eval":
        return _remove_eval(original_line, finding)

    if fix_type == "remove_exec":
        return _remove_exec(original_line, finding)

    if fix_type == "add_logging":
        return _replace_print_with_logging(original_line, finding)

    if fix_type == "remove_debugger":
        return _remove_debugger(original_line, finding)

    if fix_type == "remove_console_log":
        return _comment_out(original_line, finding)

    if fix_type == "add_test_docstring":
        return _add_test_docstring(lines, line_idx, finding)

    return None


def _classify_fix(finding: Finding) -> str:
    """Classify what kind of fix is needed.

    Rule IDs are authoritative when present. The message fallbacks use word
    boundaries so "evaluation" no longer looks like eval() and "keyword" no
    longer looks like an API key.
    """
    rule_id = finding.rule_id or ""
    msg = finding.message.lower()

    if rule_id == "SECU-201":
        return "remove_eval"
    if rule_id == "SECU-202":
        return "remove_exec"
    if re.match(r"^SECU-1\d\d$", rule_id):
        return "replace_secret"
    if rule_id == "POL-203":
        return "remove_debugger"
    if rule_id == "POL-202":
        return "add_logging"
    if rule_id == "TST-102":
        return "add_test_docstring"

    if re.search(r"\beval\s*\(", msg):
        return "remove_eval"
    if re.search(r"\bexec\s*\(", msg):
        return "remove_exec"
    if re.search(r"\bdebugger\b", msg):
        return "remove_debugger"
    if re.search(r"console\.log", msg):
        return "remove_console_log"
    if re.search(r"\bprint\s*\(", msg):
        return "add_logging"
    if re.search(r"\b(api[_-]?key|secret|password|passwd|pwd|token)\b", msg):
        return "replace_secret"
    if re.search(r"\bdocstring\b", msg):
        return "add_test_docstring"

    return "unknown"


def _remove_line(lines: list, idx: int) -> str:
    """Remove a line entirely."""
    return ""


def _replace_secret(line: str, finding: Finding) -> str:
    """Replace a hardcoded secret with an environment variable."""
    # Match: var_name = "secret_value"
    match = re.match(r'^(\s*)(\w+)\s*[:=]\s*["\']([^"\']+)["\']', line)
    if match:
        indent, var_name, _ = match.groups()
        return '{}{} = os.getenv("{}")'.format(indent, var_name, var_name.upper())
    return line


def _remove_dangerous_call(line: str, name: str) -> str:
    """Replace a dangerous call with a syntactically valid, inert statement.

    Commenting out only the call left fragments such as
    ``return # eval() removed`` followed by ``# x)``, which is confusing and
    silently changes control flow. Emit a complete statement instead.
    """
    indent = re.match(r"^(\s*)", line).group(1)
    stripped = line.strip()
    if re.match(r"^return\s+" + name + r"\s*\(", stripped):
        return "{}return None  # {}() removed - security risk".format(indent, name)
    match = re.match(r"^([A-Za-z_]\w*)\s*=\s*" + name + r"\s*\(", stripped)
    if match:
        return "{}{} = None  # {}() removed - security risk".format(
            indent, match.group(1), name)
    if re.match(r"^" + name + r"\s*\(", stripped):
        return "{}pass  # {}() removed - security risk".format(indent, name)
    return "{}# {}() removed - security risk: {}".format(indent, name, stripped)


def _remove_eval(line: str, finding: Finding) -> str:
    """Replace eval() with an inert statement."""
    return _remove_dangerous_call(line, "eval")


def _remove_exec(line: str, finding: Finding) -> str:
    """Replace exec() with an inert statement."""
    return _remove_dangerous_call(line, "exec")


def _replace_print_with_logging(line: str, finding: Finding) -> str:
    """Replace print() with logging.info() (import is ensured later)."""
    match = re.match(r'^(\s*)print\((.*)\)', line)
    if match:
        indent, content = match.groups()
        return '{}logging.info({})'.format(indent, content)
    return line


def _remove_debugger(line: str, finding: Finding) -> str:
    """Remove debugger statement."""
    return re.sub(r'\bdebugger;', '# debugger removed', line)


def _comment_out(line: str, finding: Finding) -> str:
    """Comment out a line."""
    return re.sub(r'^', '# ', line, count=1)


def _add_test_docstring(lines: list, idx: int, finding: Finding) -> str:
    """Add a docstring to a test function."""
    line = lines[idx]
    # Match def test_name(...): optionally followed by content on same line
    match = re.match(r'^(\s*def\s+test_\w+\(.*\):)', line)
    if match:
        rest = line[match.end():].strip()
        indent = "    "
        docstring = '\n{}"""Add a description of what this test validates."""'.format(indent)
        if rest:
            return match.group(1) + " " + rest + docstring
        return match.group(1) + docstring
    return line


def apply_fixes(fixes: List[Tuple[Finding, str]], content: str) -> str:
    """
    Apply multiple fixes to content.

    Args:
        fixes: List of (finding, fixed_line) tuples
        content: Original file content

    Returns:
        Modified content
    """
    lines = content.split("\n")
    for finding, fixed_line in fixes:
        line_idx = (finding.line or 1) - 1
        if 0 <= line_idx < len(lines):
            lines[line_idx] = fixed_line
    fixed = _ensure_imports("\n".join(lines))

    # The heuristics are line-local, so a fix can still produce unparsable
    # code (e.g. inside a multi-line expression). Never hand back a broken
    # file: fall back to the original and let the developer fix it manually.
    if _is_valid_python(content) and not _is_valid_python(fixed):
        logger.warning(
            "Auto-fix rejected: generated code for %s would not compile",
            ", ".join(str((f.line or 0)) for f, _ in fixes),
        )
        return content
    return fixed


def _ensure_imports(content: str) -> str:
    """Add imports required by generated fixes (e.g. os for os.getenv)."""
    needs = []
    if re.search(r"\bos\.(?:getenv|environ)\b", content) and \
            not re.search(r"^\s*import\s+os\b", content, re.MULTILINE):
        needs.append("import os")
    if re.search(r"\blogging\.\w+", content) and \
            not re.search(r"^\s*import\s+logging\b", content, re.MULTILINE):
        needs.append("import logging")
    if not needs:
        return content

    lines = content.split("\n")
    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    if insert_at < len(lines):
        stripped = lines[insert_at].lstrip()
        if stripped.startswith(('"""', "'''")):
            quote = stripped[:3]
            if stripped.count(quote) >= 2 and len(stripped) > 3:
                insert_at += 1
            else:
                for j in range(insert_at + 1, len(lines)):
                    if quote in lines[j]:
                        insert_at = j + 1
                        break
    while insert_at < len(lines) and (
        lines[insert_at].strip() == "" or lines[insert_at].lstrip().startswith("#")
    ):
        insert_at += 1
    lines[insert_at:insert_at] = needs
    return "\n".join(lines)


def get_auto_fixable(findings: List[Finding]) -> List[Finding]:
    """Filter findings that can be auto-fixed."""
    return [f for f in findings if _classify_fix(f) != "unknown"]