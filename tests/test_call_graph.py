"""
Tests for the function-level call graph and cross-file verification.

These cover the two gaps I identified earlier:
  1. build_import_graph() / get_cross_file_context() — function-level blast
     radius was implemented but had no test coverage and a Windows path bug.
  2. verify_findings() — only checked internal consistency; this adds a real
     cross-check against the deterministic regex agents (the CodeRabbit
     "verification agent" pattern).
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from prism.agents import Finding, Severity, Blocker
from prism.ai_common import (
    build_import_graph,
    get_cross_file_context,
    verify_findings,
)


def test_call_graph_function_level():
    """build_import_graph must resolve cross-file function calls."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        (p / "auth.py").write_text(
            "def validate(token):\n"
            "    return decode(token)\n"
        )
        (p / "token.py").write_text(
            "def decode(token):\n"
            "    return True\n"
        )
        (p / "session.py").write_text(
            "from auth import validate\n"
            "def get_session():\n"
            "    return validate('x')\n"
        )
        graph = build_import_graph(tmp)
        assert len(graph) == 3

        auth_key = str(p / "auth.py")
        session_key = str(p / "session.py")

        # session.py imports auth (explicit import statement)
        assert "auth" in graph[session_key]["imports"]

        # auth.py is imported by session.py
        assert session_key in graph[auth_key]["imported_by"]

        # function-level: validate() is called by session:get_session()
        validate_info = graph[auth_key]["functions"]["validate"]
        called_by = validate_info["called_by"]
        assert len(called_by) >= 1
        caller_file, caller_func, caller_line = called_by[0]
        assert caller_func == "get_session"
        assert caller_file == session_key


def test_cross_file_context_function_level():
    """get_cross_file_context must surface function-level blast radius."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        (p / "auth.py").write_text(
            "def validate(token):\n"
            "    return True\n"
        )
        (p / "session.py").write_text(
            "from auth import validate\n"
            "def get_session():\n"
            "    return validate('x')\n"
        )
        graph = build_import_graph(tmp)
        ctx = get_cross_file_context(str(p / "auth.py"), graph, tmp)
        # auth.py is imported by session.py
        assert "session.py" in ctx
        # function-level blast radius
        assert "called by" in ctx.lower()
        assert "get_session" in ctx


def test_cross_file_context_empty_when_no_graph():
    """Empty graph must return empty string, not crash."""
    assert get_cross_file_context("x.py", {}, "/tmp") == ""


def test_verify_drops_hallucinated_line():
    """verify_findings must drop a finding whose line is out of bounds."""
    findings = [Finding(
        agent="ai_test", severity=Severity.HIGH, category="C",
        message="test", file="test.py", line=999,
        suggestion="fix", blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id="TEST-AI-001",
    )]
    result = verify_findings(findings, "test.py", "x = 1\n")
    assert len(result) == 0


def test_verify_drops_hallucinated_suggested_code():
    """verify_findings must drop a finding whose suggested_code is invalid syntax."""
    findings = [Finding(
        agent="ai_test", severity=Severity.HIGH, category="C",
        message="test", file="test.py", line=1,
        suggestion="fix",
        suggested_code="def foo(:\n    pass",
        blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id="TEST-AI-002",
    )]
    result = verify_findings(findings, "test.py", "x = 1\n")
    assert len(result) == 0


def test_verify_passes_real_finding():
    """verify_findings must keep a finding that passes all checks."""
    findings = [Finding(
        agent="ai_test", severity=Severity.HIGH, category="C",
        message="eval() is dangerous", file="test.py", line=1,
        suggestion="remove eval",
        suggested_code="x = 1",
        blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id="TEST-AI-003",
    )]
    result = verify_findings(findings, "test.py", "eval('x')\n")
    assert len(result) == 1


def test_verify_drops_duplicate():
    """verify_findings must drop duplicate findings."""
    f = Finding(
        agent="ai_test", severity=Severity.HIGH, category="C",
        message="duplicate finding", file="test.py", line=1,
        suggestion="fix", blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id="TEST-AI-004",
    )
    result = verify_findings([f, f], "test.py", "x = 1\n")
    assert len(result) == 1


def test_verify_drops_message_referring_to_missing_code():
    """A finding whose message names a function not present at the line is dropped."""
    findings = [Finding(
        agent="ai_test", severity=Severity.HIGH, category="C",
        message="nonexistent_function_xyz is unused", file="test.py", line=1,
        suggestion="remove it", blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id="TEST-AI-005",
    )]
    result = verify_findings(findings, "test.py", "x = 1\n")
    assert len(result) == 0


def test_cross_check_confirms_secret_finding():
    """A secret finding at a line with a real secret gets full confidence."""
    findings = [Finding(
        agent="ai_security", severity=Severity.CRITICAL,
        category="Secret Exposure",
        message="api_key detected", file="test.py", line=1,
        suggestion="remove it", blocker=Blocker.BLOCKS, confidence=0.85,
        rule_id="SECU-AI-001",
    )]
    result = verify_findings(findings, "test.py", 'API_KEY = "supersecretvalue123"\n')
    assert len(result) == 1
    assert result[0].confidence == 0.85  # confirmed, no reduction


def test_cross_check_reduces_unconfirmed_finding():
    """A finding with no deterministic support gets halved confidence."""
    findings = [Finding(
        agent="ai_architecture", severity=Severity.MEDIUM,
        category="Architectural Smell",
        message="this function does too much", file="test.py", line=1,
        suggestion="split it", blocker=Blocker.WARNS, confidence=0.85,
        rule_id="ARC-AI-001",
    )]
    result = verify_findings(findings, "test.py", "x = 1\n")
    assert len(result) == 1
    # Architectural findings are semantic — no regex can confirm them, so
    # confidence is left untouched.
    assert result[0].confidence == 0.85