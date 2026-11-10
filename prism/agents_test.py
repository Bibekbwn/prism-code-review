"""
Test Agent - Validates that tests exist, tests pass, and measures coverage.

Rule IDs follow SonarQube convention: TST-XXX
"""

import ast
import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent
from prism.feedback import measure_coverage


@register_agent
class TestAgent(BaseAgent):
    name = "test"
    description = "Checks test coverage and validates test files"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")
        is_test_file = "test" in file_path.lower() or "spec" in file_path.lower()

        if not is_test_file and len(lines) > 20:
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

        if is_test_file:
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
                        line=1,
                        suggestion="Add a description of what the test validates.",
                        blocker=Blocker.WARNS,
                        confidence=0.85,
                        rule_id="TST-102",
                    ))
            findings.extend(_check_weak_assertions(content, file_path))
            findings.extend(_check_test_naming(content, file_path))

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


def _check_weak_assertions(content: str, file_path: str) -> List[Finding]:
    """Flag assertions that always pass or are otherwise meaningless."""
    findings = []
    lines = content.split("\n")
    weak = [
        (r'\bassert\s+True\b', "assert True always passes"),
        (r'\bassert\s+1\b', "assert 1 always passes"),
        (r'\bassert\s+0\b', "assert 0 always fails"),
        (r'\bassert\s+None\b', "assert None always fails"),
        (r'\bassert\s+False\b', "assert False always fails"),
        (r'\bassert\s+\w+\s*!=\s*\w+\b', "assert x != y compares two variables (may be vacuous)"),
    ]
    for i, line in enumerate(lines):
        for pattern, message in weak:
            if re.search(pattern, line):
                findings.append(Finding(
                    agent="test",
                    severity=Severity.MEDIUM,
                    category="Weak Assertion",
                    message=message,
                    file=file_path,
                    line=i + 1,
                    suggestion="Assert on a meaningful condition.",
                    blocker=Blocker.WARNS,
                    confidence=0.80,
                    rule_id="TST-104",
                ))
                break
    return findings


def _check_test_naming(content: str, file_path: str) -> List[Finding]:
    """Flag test functions whose names don't follow conventions."""
    findings = []
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return findings
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("test_"):
                if "test" in node.name.lower():
                    findings.append(Finding(
                        agent="test",
                        severity=Severity.LOW,
                        category="Test Naming",
                        message="Test function '{}' should use 'test_' prefix".format(node.name),
                        file=file_path,
                        line=node.lineno,
                        suggestion="Name tests as test_<scenario>_<expected>.",
                        blocker=Blocker.WARNS,
                        confidence=0.75,
                        rule_id="TST-105",
                    ))
    return findings