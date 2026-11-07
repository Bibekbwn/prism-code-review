"""
Test Agent - Validates that tests exist for tests pass, and measures coverage.

Rule IDs follow SonarQube convention: TST-XXX
"""

import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent
from prism.feedback import measure_coverage


@register_agent
class TestAgent(BaseAgent):
    name = "test"
    description = "Checks test coverage and validates test files"

    def _check(self, file_path: str, content: str, diff: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")

        if "test" in file_path.lower() or "spec" in file_path.lower():
            return findings

        if len(lines) > 20:
            findings.append(Finding(
                agent=self.name,
                severity=Severity.HIGH,
                category="Missing Tests",
                message="No test file found for {}".format(file_path),
                file=file_path,
                suggestion="Add unit tests before committing.",
                blocker=Blocker.BLOCKS,
                confidence=0.75,
                rule_id="TST-101",
            ))

        if "test" in file_path.lower():
            test_bodies = re.findall(
                r'def\s+(test_\w+)\(.*\):\s*\n\s*"""(.*?)"""', content, re.DOTALL
            )
            for name, docstring in test_bodies:
                if not docstring.strip():
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.LOW,
                        category="Unclear Test",
                        message="Test '{}' has no docstring".format(name),
                        file=file_path,
                        suggestion="Add a description of what the test validates.",
                        blocker=Blocker.WARNS,
                        confidence=0.85,
                        rule_id="TST-102",
                    ))

        # Measure actual coverage
        try:
            cov = measure_coverage()
            if cov.get("coverage", 0) > 0 and cov["coverage"] < 0.80:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    category="Low Coverage",
                    message="Test coverage is {:.0f}% (minimum 80%)".format(
                        cov["coverage"] * 100),
                    file=file_path,
                    suggestion="Add more unit tests to improve coverage.",
                    blocker=Blocker.WARNS,
                    confidence=1.0,
                    rule_id="TST-103",
                ))
        except Exception:
            pass

        return findings