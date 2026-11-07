"""
Policy Agent - Checks compliance with project policies,
license headers, copyright notices, and code ownership rules.

Rule IDs follow SonarQube convention: POL-XXX
"""

import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent


@register_agent
class PolicyAgent(BaseAgent):
    name = "policy"
    description = "Checks compliance with project policies and standards"

    def __init__(self, require_header: bool = True, allowed_licenses: list = None):
        self.require_header = require_header
        self.allowed_licenses = allowed_licenses or ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]

    def _check(self, file_path: str, content: str, diff: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")

        if self.require_header and file_path.endswith(
            (".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".h")
        ):
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
            (r"print\(", "Use logging module instead of print()", "POL-202"),
            (r"debugger;", "Remove debugger statement", "POL-203"),
            (r"alert\(", "Remove alert() - use proper UI components", "POL-204"),
        ]
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

        return findings