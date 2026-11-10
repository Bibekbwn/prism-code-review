"""
Integration tests for PRISM auto-fix, SCA, lint, and JSON output.
"""

import pytest
import sys
import os
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from prism.agents import Finding, Severity, Blocker
from prism.autofix import generate_fix, apply_fixes, get_auto_fixable, _classify_fix
from prism.feedback import scan_dependencies, measure_coverage


class TestAutoFix:
    def test_classify_fix_secret(self):
        f = Finding(
            agent="security", severity=Severity.CRITICAL,
            category="Secret Exposure", message="Possible api key detected",
            file="test.py", line=1, rule_id="SECU-101",
        )
        assert _classify_fix(f) == "replace_secret"

    def test_classify_fix_eval(self):
        f = Finding(
            agent="security", severity=Severity.HIGH,
            category="Dangerous Pattern", message="Use of eval()",
            file="test.py", line=1, rule_id="SECU-201",
        )
        assert _classify_fix(f) == "remove_eval"

    def test_classify_fix_debugger(self):
        f = Finding(
            agent="policy", severity=Severity.LOW,
            category="Banned Pattern", message="Remove debugger statement",
            file="test.py", line=1, rule_id="POL-203",
        )
        assert _classify_fix(f) == "remove_debugger"

    def test_generate_fix_secret(self):
        content = 'API_KEY = "sk-1234567890abcdef"'
        f = Finding(
            agent="security", severity=Severity.CRITICAL,
            category="Secret Exposure", message="Possible api key detected",
            file="test.py", line=1, rule_id="SECU-101",
        )
        fixed = generate_fix(f, content)
        assert fixed is not None
        assert "os.getenv" in fixed

    def test_generate_fix_eval(self):
        content = 'eval("print(1)")'
        f = Finding(
            agent="security", severity=Severity.HIGH,
            category="Dangerous Pattern", message="Use of eval()",
            file="test.py", line=1, rule_id="SECU-201",
        )
        fixed = generate_fix(f, content)
        assert fixed is not None
        assert "# eval() removed" in fixed

    def test_apply_fixes(self):
        content = 'line1\nline2\nline3'
        f = Finding(
            agent="security", severity=Severity.CRITICAL,
            category="Secret Exposure", message="test",
            file="test.py", line=2, rule_id="SECU-101",
        )
        result = apply_fixes([(f, "FIXED")], content)
        assert "FIXED" in result
        assert "line1" in result
        assert "line3" in result


class TestSCA:
    def test_scan_dependencies_axios(self):
        content = '{"dependencies": {"axios": "^0.21.0"}}'
        findings = scan_dependencies("package.json", content)
        assert len(findings) > 0
        assert any("3749" in f["rule_id"] for f in findings)

    def test_scan_dependencies_clean(self):
        content = '{"dependencies": {"express": "^4.18.0"}}'
        findings = scan_dependencies("package.json", content)
        assert len(findings) == 0

    def test_scan_dependencies_no_manifest(self):
        findings = scan_dependencies("src/main.py", "print('hello')")
        assert len(findings) == 0


class TestJSONOutput:
    def test_json_output_structure(self):
        from prism.cli import _json_output
        from prism.agents import AgentResult

        results = [AgentResult(
            agent_name="test",
            findings=[Finding(
                agent="test", severity=Severity.HIGH,
                category="Test", message="test finding",
                file="test.py", line=1, rule_id="TEST-001",
            )],
            passed=False,
        )]
        config = {'block_on': ['critical', 'high'], 'confidence_threshold': 0.7}
        output = _json_output(results, config, {"test.py": 0.5}, "test.py")

        assert "file" in output
        assert "findings" in output
        assert "commit_allowed" in output
        assert output["total_findings"] == 1
        assert output["blocking"] == 1
        assert output["commit_allowed"] is False


class TestLint:
    def test_duplication_detection(self):
        from prism.agents_quality import _check_duplication
        content = (
            "def foo():\n"
            "    x = 1\n"
            "    y = 2\n"
            "    z = 3\n"
            "    return x + y + z\n"
            "\n"
            "def bar():\n"
            "    x = 1\n"
            "    y = 2\n"
            "    z = 3\n"
            "    return x + y + z\n"
        )
        findings = _check_duplication(content, "test.py")
        assert len(findings) > 0
        assert findings[0].category == "Duplication"

    def test_naming_convention_python(self):
        from prism.agents_quality import _check_naming
        content = "badName = 1\n"
        findings = _check_naming(content, "test.py")
        assert len(findings) > 0
        assert findings[0].category == "Naming Convention"

    def test_imports_unused(self):
        from prism.agents_quality import _check_imports
        content = "import os\nimport sys\nprint(sys.path)\n"
        findings = _check_imports(content, "test.py")
        assert any(f.category == "Unused Import" for f in findings)


class TestCoverage:
    def test_measure_coverage_no_tests(self):
        # Should not crash even with no tests
        with tempfile.TemporaryDirectory() as tmpdir:
            result = measure_coverage(tmpdir)
            assert "coverage" in result
            assert "tests_run" in result