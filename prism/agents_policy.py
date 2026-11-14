"""
Policy Agent - Checks compliance with project policies,
license headers, copyright notices, and code ownership rules.

Rule IDs follow SonarQube convention: POL-XXX

These are style/policy preferences, not bugs, so everything here is LOW
severity and never blocks. The rules that are pure noise on most projects
(SPDX headers, print(), console.log, TODO(issue-ref) formatting) are off by
default and opt-in via prism.json:

  "policy": {
    "headers": true,          # require copyright/SPDX headers
    "banned_console": true,   # flag console.log in JS/TS
    "check_print": true,      # flag print() outside CLI entry points
    "check_todo_refs": true   # enforce TODO(PROJECT-123) format
  }
"""

import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent
from prism.langs import lang_for, strip_literals

# Copyright/SPDX header checks are opt-in via prism.json:
#   "policy": {"headers": true}
# They fired on every source file, which is pure noise for projects that do
# not use SPDX headers.
HEADER_CHECKS_ENABLED = False

# Everything that is a preference rather than a defect is opt-in.
BANNED_CONSOLE_ENABLED = False
CHECK_PRINT_ENABLED = False
CHECK_TODO_REFS_ENABLED = False


@register_agent
class PolicyAgent(BaseAgent):
    name = "policy"
    description = "Checks compliance with project policies and standards"

    def __init__(self, require_header: bool = True, allowed_licenses: list = None,
               policy: dict = None):
        self.require_header = require_header
        self.allowed_licenses = allowed_licenses or ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
        self._policy = policy or {}

    @property
    def policy(self):
        """Policy options, kept on the instance so tests can inject them."""
        return self._policy

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")
        policy = self._policy

        headers_on = HEADER_CHECKS_ENABLED or policy.get("headers", False)
        console_on = BANNED_CONSOLE_ENABLED or policy.get("banned_console", False)
        print_on = CHECK_PRINT_ENABLED or policy.get("check_print", False)
        todo_refs_on = CHECK_TODO_REFS_ENABLED or policy.get("check_todo_refs", False)

        if headers_on and self.require_header and lang_for(file_path) is not None:
            first_10 = "\n".join(lines[:10])
            if not re.search(r"Copyright\s+\(c\)", first_10):
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.LOW,
                    category="Missing Header",
                    message="Missing copyright notice in file header",
                    file=file_path,
                    line=1,
                    suggestion="Add copyright header with year and author.",
                    blocker=Blocker.WARNS,
                    confidence=1.0,
                    rule_id="POL-101",
                ))

        banned = [
            (r"debugger;", "Remove debugger statement", "POL-203"),
            (r"alert\(", "Remove alert() - use proper UI components", "POL-204"),
        ]
        if console_on:
            banned.append(
                (r"console\.log\(", "Use structured logging instead of console.log",
                 "POL-201")
            )
        # print() is legitimate in CLI tools and entry points. Only flag it
        # in library/module code that has no argparse or __main__ guard, and
        # only when the developer opted in.
        is_cli_entry = bool(
            re.search(r'argparse|__main__|def main\b', content)
        )
        docstrings = _docstring_lines(content)
        spec = lang_for(file_path)
        for pattern, message, rule_id in banned:
            for i, line in enumerate(lines):
                if _matches_code(pattern, line, i + 1, docstrings, spec):
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.LOW,
                        category="Banned Pattern",
                        message=message,
                        file=file_path,
                        line=i + 1,
                        suggestion=message,
                        blocker=Blocker.WARNS,
                        confidence=1.0,
                        rule_id=rule_id,
                    ))
        if print_on and not is_cli_entry:
            for i, line in enumerate(lines):
                if _matches_code(r'print\(', line, i + 1, docstrings, spec):
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.LOW,
                        category="Banned Pattern",
                        message="Use logging module instead of print()",
                        file=file_path,
                        line=i + 1,
                        suggestion="Use logging module instead of print()",
                        blocker=Blocker.WARNS,
                        confidence=1.0,
                        rule_id="POL-202",
                    ))

        if todo_refs_on:
            for i, line in enumerate(lines):
                match = re.search(r'TODO\s*\((\w+)\)', strip_literals(line, spec))
                if match:
                    issue_ref = match.group(1)
                    if not re.match(r'^[A-Z]+-\d+$', issue_ref):
                        findings.append(Finding(
                            agent=self.name,
                            severity=Severity.LOW,
                            category="Invalid Issue Reference",
                            message="TODO references '{}' - use format PROJECT-123".format(issue_ref),
                            file=file_path,
                            line=i + 1,
                            suggestion="Use valid issue tracker reference.",
                            blocker=Blocker.WARNS,
                            confidence=0.90,
                            rule_id="POL-205",
                        ))

        if headers_on:
            findings.extend(_check_license_header(content, file_path, self.allowed_licenses))
        findings.extend(_check_branch_naming(file_path))

        return findings


# SPDX-style license identifiers recognized in source headers.
SPDX_LICENSES = {
    "MIT": r"MIT",
    "Apache-2.0": r"Apache[\-\s]?2\.0",
    "BSD-3-Clause": r"BSD[\-\s]?3[\-\s]?Clause",
    "ISC": r"\bISC\b",
    "GPL-3.0": r"GPL[\-\s]?3\.0",
    "MPL-2.0": r"MPL[\-\s]?2\.0",
}


def _strip_literals(line: str, spec=None) -> str:
    """Remove single-line string/regex literals so patterns only match code.

    Which characters open a comment and a string is a property of the language:
    a rule that only knew ``#`` read a commented-out ``debugger;`` in Go or Rust
    as a real statement.
    """
    return strip_literals(line, spec)


def _docstring_lines(content: str) -> set:
    """Line numbers (1-based) that belong to a module/class/function docstring.

    A per-line stripper cannot know it is inside a triple-quoted block, so a
    rule word quoted in a docstring (this module's own docs mention
    `debugger;`) was reported as a real statement.
    """
    import ast

    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return set()

    lines = set()

    def _mark(node):
        body = getattr(node, "body", None)
        if not body:
            return
        first = body[0]
        if (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            for n in range(first.lineno, (first.end_lineno or first.lineno) + 1):
                lines.add(n)

    _mark(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _mark(node)
    return lines


def _matches_code(pattern, line, lineno=None, docstrings=None, spec=None):
    """True when ``pattern`` matches the line's code, ignoring literals."""
    if docstrings and lineno in docstrings:
        return False
    return re.search(pattern, strip_literals(line, spec)) is not None


def _check_license_header(content: str, file_path: str, allowed_licenses: list) -> List[Finding]:
    """Verify the file header declares an allowed SPDX license."""
    if lang_for(file_path) is None:
        return []
    findings = []
    first_20 = "\n".join(content.split("\n")[:20])
    found = None
    for lic, pattern in SPDX_LICENSES.items():
        if re.search(pattern, first_20):
            found = lic
            break
    if found is None:
        findings.append(Finding(
            agent="policy",
            severity=Severity.MEDIUM,
            category="Missing License",
            message="No SPDX license identifier found in header",
            file=file_path,
            line=1,
            suggestion="Add an SPDX license identifier (e.g. 'SPDX-License-Identifier: MIT').",
            blocker=Blocker.WARNS,
            confidence=0.80,
            rule_id="POL-206",
        ))
    elif allowed_licenses and found not in allowed_licenses:
        findings.append(Finding(
            agent="policy",
            severity=Severity.MEDIUM,
            category="Disallowed License",
            message="License '{}' is not in allowed list {}".format(found, allowed_licenses),
            file=file_path,
            line=1,
            suggestion="Use one of: {}".format(", ".join(allowed_licenses)),
            blocker=Blocker.WARNS,
            confidence=0.85,
            rule_id="POL-207",
        ))
    return findings


def _check_branch_naming(file_path: str) -> List[Finding]:
    """Flag source files whose path implies a non-standard branch name."""
    findings = []
    # Only applies to files that live under a branch-shaped directory.
    m = re.search(r'(?:^|[/\\])(feature|fix|hotfix|docs|chore|refactor|test|build|ci)(?:[/\\]|$)', file_path)
    if m:
        prefix = m.group(1)
        if prefix not in ("feature", "fix", "hotfix", "docs", "chore", "refactor", "test", "build", "ci"):
            findings.append(Finding(
                agent="policy",
                severity=Severity.LOW,
                category="Branch Naming",
                message="Branch prefix '{}' not in conventional set".format(prefix),
                file=file_path,
                line=1,
                suggestion="Use: feature/, fix/, hotfix/, docs/, chore/, refactor/, test/, build/, ci/.",
                blocker=Blocker.WARNS,
                confidence=0.60,
                rule_id="POL-208",
            ))
    return findings