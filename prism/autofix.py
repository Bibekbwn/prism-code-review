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
from prism.langs import lang_for
from prism.logging_config import logger

# A declaration is a name preceded by modifiers, a type, or a qualifier
# (`const token`, `String apiKey`, `self.password`). Taking the name from the
# start of the line got the boundary wrong: `String apiKey` produced
# `StringapiKey` and `\tapiKey :=` produced the single character `y`.
_SECRET_ASSIGN = re.compile(
    r'^(?P<head>\s*(?:[\w$]+(?:[\s*&.]*|::))*?)'
    r'(?P<name>\$?[A-Za-z_]\w*)'
    r'(?P<op>\s*(?::=|(?<![=!<>:])=(?!=)|:(?!=))\s*)'
    r'(?P<q>["\'])(?P<lit>.*?)(?P=q)(?P<tail>.*)$')


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
    spec = _spec_for(finding)

    if fix_type == "remove_line":
        return _remove_line(lines, line_idx)

    if fix_type == "replace_secret":
        return _replace_secret(original_line, finding, spec)

    if fix_type == "remove_eval":
        return _remove_eval(original_line, finding, spec)

    if fix_type == "remove_exec":
        return _remove_exec(original_line, finding, spec)

    if fix_type == "add_logging":
        return _replace_print_with_logging(original_line, finding, spec)

    if fix_type == "remove_debugger":
        return _remove_debugger(original_line, finding, spec)

    if fix_type == "remove_console_log":
        return _comment_out(original_line, finding, spec)

    if fix_type == "add_test_docstring":
        return _add_test_docstring(lines, line_idx, finding)

    return None


def _spec_for(finding):
    """The language of the file a finding came from, or None if it is not source."""
    return lang_for(getattr(finding, "file", "") or "")


def _comment_prefix(spec):
    """How a language starts a comment, for fixes that must disable a line."""
    if spec is None or not spec.line_comments:
        return "#"
    return spec.line_comments[0]


def _is_python(spec):
    return spec is None or spec.name == "python"


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
    # QUAL-110 is "missing docstring": a real docstring needs the function's
    # purpose, which cannot be invented from the name. `add_test_docstring`
    # only ever applied to TST-102, and routing QUAL-110 here produced a
    # suggestion that just echoed the def line back.
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
    if re.search(r"\b(api[_-]?secret|secret|password|passwd|pwd|token)\b", msg):
        return "replace_secret"
    # "docstring" alone is not enough: only test docstrings can be generated.
    if re.search(r"\bdocstring\b", msg) and "test" in msg:
        return "add_test_docstring"

    return "unknown"


def _remove_line(lines: list, idx: int) -> str:
    """Remove a line entirely."""
    return ""


def _replace_secret(line: str, finding: Finding, spec=None) -> str:
    """Replace a hardcoded secret with a read from the environment.

    The declaration is left as it is and only the literal is swapped, so
    ``apiKey := "..."`` keeps its ``:=`` and its trailing ``;`` while the value
    becomes the language's own lookup (``os.Getenv("APIKEY")`` in Go,
    ``process.env.APIKEY`` in JS). Emitting ``os.getenv`` into a Go file would
    not compile, which is worse than offering no fix at all.
    """
    env_read = spec.env_read if spec is not None else 'os.getenv("{name}")'
    match = _SECRET_ASSIGN.match(line)
    if not match:
        return line
    # PHP declares `$key`; the sigil is not part of the variable's name.
    name = re.sub(r"[^A-Za-z0-9]", "_", match.group("name").lstrip("$")).upper()
    return (match.group("head") + match.group("name") + match.group("op")
            + env_read.format(name=name) + match.group("tail"))


def _remove_dangerous_call(line: str, name: str, spec=None) -> str:
    """Replace a dangerous call with a syntactically valid, inert statement.

    Commenting out only the call left fragments such as
    ``return # eval() removed`` followed by ``# x)``, which is confusing and
    silently changes control flow. Emit a complete statement instead.

    ``pass`` and ``return None`` are Python, so elsewhere the line is disabled
    with the language's own comment marker: it cannot be wrong about syntax
    because nothing new is executed.
    """
    indent = re.match(r"^(\s*)", line).group(1)
    stripped = line.strip()
    if not _is_python(spec):
        return "{}{} {}() removed - security risk: {}".format(
            indent, _comment_prefix(spec), name, stripped)
    if re.match(r"^return\s+" + name + r"\s*\(", stripped):
        return "{}return None  # {}() removed - security risk".format(indent, name)
    match = re.match(r"^([A-Za-z_]\w*)\s*=\s*" + name + r"\s*\(", stripped)
    if match:
        return "{}{} = None  # {}() removed - security risk".format(
            indent, match.group(1), name)
    if re.match(r"^" + name + r"\s*\(", stripped):
        return "{}pass  # {}() removed - security risk".format(indent, name)
    return "{}# {}() removed - security risk: {}".format(indent, name, stripped)


def _remove_eval(line: str, finding: Finding, spec=None) -> str:
    """Replace eval() with an inert statement."""
    return _remove_dangerous_call(line, "eval", spec)


def _remove_exec(line: str, finding: Finding, spec=None) -> str:
    """Replace exec() with an inert statement."""
    return _remove_dangerous_call(line, "exec", spec)


def _replace_print_with_logging(line: str, finding: Finding, spec=None) -> str:
    """Replace print() with logging.info() (import is ensured later).

    ``logging`` is Python's module; in another language the line is disabled and
    the developer is pointed at the language's own logger.
    """
    match = re.match(r'^(\s*)print\((.*)\)', line)
    if match and _is_python(spec):
        indent, content = match.groups()
        return '{}logging.info({})'.format(indent, content)
    if match:
        indent, content = match.groups()
        return "{}{} print() removed - use a logging framework: {}".format(
            indent, _comment_prefix(spec), content)
    return line


def _remove_debugger(line: str, finding: Finding, spec=None) -> str:
    """Comment out a debugger statement.

    Only matches `debugger;` when it is the statement itself, not when the
    text appears inside a string or regex literal (e.g. a rule definition
    containing the word "debugger"), which would corrupt the line.
    """
    # A quoted literal before the keyword means it is data, not code.
    stripped = line.lstrip()
    if stripped.startswith(('"', "'", "r'", 'r"', "b'", 'b"', "f'", 'f"')):
        return line
    prefix = _comment_prefix(spec)
    return re.sub(r'^(\s*)debugger;', r'\g<1>' + prefix + ' debugger removed', line)


def _comment_out(line: str, finding=None, spec=None) -> str:
    """Comment out a line, using the language's own comment marker."""
    if spec is None:
        spec = _spec_for(finding)
    return re.sub(r'^', _comment_prefix(spec) + " ", line, count=1)


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
    # `import os` is Python's way of getting the lookup; adding it to a Go or
    # JS file would be a syntax error in a language it does not belong to.
    spec = _spec_for(fixes[0][0]) if fixes else None
    if _is_python(spec):
        fixed = _ensure_imports("\n".join(lines))
    elif spec is not None and spec.name == "go":
        # `os.Getenv` needs `import "os"`. A single import statement is legal
        # anywhere after the package clause, so this cannot break the file.
        fixed = _ensure_go_imports("\n".join(lines))
    else:
        fixed = "\n".join(lines)

    # The heuristics are line-local, so a fix can still produce unparsable
    # code (e.g. inside a multi-line expression). Never hand back a broken
    # file: fall back to the original and let the developer fix it manually.
    if _is_python(spec) and _is_valid_python(content) \
            and not _is_valid_python(fixed):
        logger.warning(
            "Auto-fix rejected: generated code for %s would not compile",
            ", ".join(str((f.line or 0)) for f, _ in fixes),
        )
        return content
    return fixed


def _ensure_go_imports(content: str) -> str:
    """Add ``import "os"`` when a generated fix calls ``os.Getenv``.

    Go has no implicit imports, so a fix that calls ``os.Getenv`` in a file
    that does not already import ``os`` would not build. Any ``import`` after
    the package clause is legal, including a second one, so this is a plain
    insertion rather than an edit of an existing import block.
    """
    if not re.search(r"\bos\.Getenv\b", content):
        return content
    # Either form: `import "os"`, or the spec on its own line inside `import (...)`.
    # Importing the same package twice is a compile error in Go, so this guard
    # has to see through the parenthesised form.
    spec_line = r'^\s*(?:\w+\s+)?"os"\s*$'
    if re.search(r'^\s*import\s+(?:\w+\s+)?"os"\s*$', content, re.MULTILINE) or \
            re.search(spec_line, content, re.MULTILINE):
        return content
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if re.match(r"^\s*package\s+\w+", line):
            lines.insert(i + 1, "")
            lines.insert(i + 2, 'import "os"')
            return "\n".join(lines)
    return content


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