"""
Auto-fix engine - Generates corrected code for auto-fixable findings.

Based on GitHub Copilot's "suggested changes" and CodeRabbit's "One-Click Fix":
- AI generates corrected code snippets
- Developer reviews before applying
- Changes are attributed to the developer, not committed automatically
"""

import re
from typing import List, Optional, Tuple
from prism.agents import Finding, Severity


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
    """Classify what kind of fix is needed."""
    rule_id = finding.rule_id or ""
    msg = finding.message.lower()

    if "eval" in msg:
        return "remove_eval"
    if "debugger" in msg:
        return "remove_debugger"
    if "console.log" in msg:
        return "remove_console_log"
    if "print(" in msg:
        return "add_logging"
    if "secret" in msg or "key" in msg or "token" in msg or "password" in msg:
        return "replace_secret"
    if "docstring" in msg:
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


def _remove_eval(line: str, finding: Finding) -> str:
    """Replace eval() with a safer alternative."""
    return re.sub(r'\beval\s*\(', '# eval() removed - security risk\n# ', line)


def _replace_print_with_logging(line: str, finding: Finding) -> str:
    """Replace print() with logger call."""
    match = re.match(r'^(\s*)print\((.*)\)', line)
    if match:
        indent, content = match.groups()
        return '{}logger.info({})'.format(indent, content)
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
    return "\n".join(lines)


def get_auto_fixable(findings: List[Finding]) -> List[Finding]:
    """Filter findings that can be auto-fixed."""
    return [f for f in findings if _classify_fix(f) != "unknown"]