"""
Policy Agent - Checks compliance with project policies,
license headers, copyright notices, and code ownership rules.

Rule IDs follow SonarQube convention: POL-XXX
"""

import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent

# Copyright/SPDX header checks are opt-in via prism.json:
#   "policy": {"headers": true}
# They fired on every source file, which is pure noise for projects that do
# not use SPDX headers.
HEADER_CHECKS_ENABLED = False


@register_agent
class PolicyAgent(BaseAgent):
    name = "policy"
    description = "Checks compliance with project policies and standards"

    def __init__(self, require_header: bool = True, allowed_licenses: list = None):
        self.require_header = require_header
        self.allowed_licenses = allowed_licenses or ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")

        if (HEADER_CHECKS_ENABLED and self.require_header and file_path.endswith(
            (".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".h")
        )):
            first_10 = "\n".join(lines[:10])
            if not re.search(r"Copyright\s+\(c\)", first_10):
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
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
            (r"console\.log\(", "Use structured logging instead of console.log", "POL-201"),
            (r"debugger;", "Remove debugger statement", "POL-203"),
            (r"alert\(", "Remove alert() - use proper UI components", "POL-204"),
        ]
        # print() is legitimate in CLI tools and entry points. Only flag it
        # in library/module code that has no argparse or __main__ guard.
        is_cli_entry = bool(
            re.search(r'argparse|__main__|def main\b', content)
        )
        for pattern, message, rule_id in banned:
            for i, line in enumerate(lines):
                if re.search(pattern, line):
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
        if not is_cli_entry:
            for i, line in enumerate(lines):
                if re.search(r'print\(', line):
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

        for i, line in enumerate(lines):
            match = re.search(r'TODO\s*\((\w+)\)', line)
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

        if HEADER_CHECKS_ENABLED:
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


def _check_license_header(content: str, file_path: str, allowed_licenses: list) -> List[Finding]:
    """Verify the file header declares an allowed SPDX license."""
    if not file_path.endswith((".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".h")):
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