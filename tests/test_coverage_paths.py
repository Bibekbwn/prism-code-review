"""Coverage tests for modules the review paths exercise but the unit suite missed.

These are fast, offline tests: reports, cache, config, LSP plumbing, and the
regex-agent rule helpers. They exist to make `pytest --cov=prism` meaningful
enough to gate on (see .github/workflows/ci-cd.yml).
"""

import io
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _git(cwd, *args):
    subprocess.run(["git"] + list(args), cwd=str(cwd), check=True,
                   capture_output=True, text=True)


class TestReports:
    def test_save_load_index_and_summary(self, tmp_path, monkeypatch):
        from prism import reports

        monkeypatch.chdir(tmp_path)
        rid = reports.save_report(
            files_reviewed=["a.py"],
            findings=[{"agent": "security", "severity": "critical",
                       "rule_id": "SECU-201", "problem": "eval"}],
            risk_score=0.9, blocking=1, commit_allowed=False,
            commit_hash="abc123", branch="feature/x")

        loaded = reports.load_report(rid)
        assert loaded["blocking"] == 1
        assert loaded["findings"][0]["rule_id"] == "SECU-201"
        assert reports.load_report("missing-id") is None

        index = reports.load_index()
        assert [r["id"] for r in index["reports"]] == [rid]
        assert [r["id"] for r in reports.get_recent_reports(1)] == [rid]

        history = reports.get_findings_history()
        assert history["total_reviews"] == 1
        assert history["findings_by_severity"]["critical"] == 1
        assert history["findings_by_agent"]["security"] == 1
        assert history["findings_by_rule"]["SECU-201"] == 1
        assert history["commits_blocked"] == 1

        summary = reports.get_report_summary()
        assert "Total reviews: 1" in summary
        assert "Top Rules:" in summary

    def test_delete_and_clear(self, tmp_path, monkeypatch):
        from prism import reports

        monkeypatch.chdir(tmp_path)
        rid = reports.save_report(["a.py"], [], 0.0, 0, True)
        assert reports.delete_report(rid) is True
        assert reports.delete_report(rid) is False

        reports.save_report(["b.py"], [], 0.0, 0, True)
        assert reports.clear_reports() == 1
        assert reports.clear_reports() == 0


class TestCodebaseCache:
    def test_sha_and_roundtrip(self, tmp_path, monkeypatch):
        from prism import codebase_cache as cc

        monkeypatch.chdir(tmp_path)
        target = tmp_path / "a.py"
        target.write_text("x = 1\n")

        assert len(cc._file_sha(target)) == 64
        assert cc._file_sha(tmp_path / "missing.py") is None

        cache = {}
        assert cc.get_cached_findings("a.py", cache) is None
        cc.cache_findings("a.py", [], cache)
        assert cc.get_cached_findings("a.py", cache) == []

        stats = cc.get_cache_stats()
        assert stats["files_cached"] == 1
        assert stats["exists"] is True
        assert cc.clear_cache() == 1
        assert cc.get_cache_stats()["exists"] is False

    def test_changed_files_uses_git(self, tmp_path, monkeypatch):
        from prism import codebase_cache as cc

        monkeypatch.chdir(tmp_path)
        _git(tmp_path, "init", "-q")
        _git(tmp_path, "config", "user.email", "t@example.com")
        _git(tmp_path, "config", "user.name", "T")
        (tmp_path / "a.py").write_text("x = 1\n")
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "init")

        changed, unchanged, cache = cc.get_changed_files()
        assert "a.py" in changed
        assert unchanged == []

        cc.cache_findings("a.py", [], cache)
        changed, unchanged, cache = cc.get_changed_files()
        assert changed == []
        assert "a.py" in unchanged

        (tmp_path / "a.py").write_text("x = 2\n")
        changed, unchanged, cache = cc.get_changed_files()
        assert "a.py" in changed

    def test_cache_path_is_inside_repo(self, tmp_path, monkeypatch):
        from prism import codebase_cache as cc

        monkeypatch.chdir(tmp_path)
        assert cc._cache_path().name == ".prism-cache.json"


class TestCliConfig:
    def test_defaults_when_no_config(self, tmp_path, monkeypatch):
        from prism.cli_config import load_config, load_deviation_policy

        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert "ai_security" in config["agents"]
        assert config["block_on"] == ["critical", "high"]
        assert load_deviation_policy() == {"deviations": []}

    def test_reads_prism_json(self, tmp_path, monkeypatch):
        from prism.cli_config import load_config

        monkeypatch.chdir(tmp_path)
        (tmp_path / "prism.json").write_text(json.dumps({"block_on": ["critical"]}))
        assert load_config()["block_on"] == ["critical"]

    def test_is_deviation(self, tmp_path, monkeypatch):
        from prism.agents import Finding, Severity
        from prism.cli_config import is_deviation, load_deviation_policy

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".prism-policy.json").write_text(json.dumps(
            {"deviations": [{"rule_id": "POL-101", "reason": "legacy"}]}))
        policy = load_deviation_policy()
        finding = Finding(agent="policy", severity=Severity.LOW,
                          category="Policy", message="header",
                          file="a.py", line=1, rule_id="POL-101")
        assert is_deviation(finding, policy) is True
        finding.rule_id = "POL-999"
        assert is_deviation(finding, policy) is False

    def test_git_helpers(self, tmp_path, monkeypatch):
        from prism.cli_config import (get_diff_files, get_diff_for_file,
                                      get_file_diff, get_staged_files)

        monkeypatch.chdir(tmp_path)
        _git(tmp_path, "init", "-q")
        _git(tmp_path, "config", "user.email", "t@example.com")
        _git(tmp_path, "config", "user.name", "T")
        (tmp_path / "a.py").write_text("x = 1\n")
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "init")

        assert get_staged_files() == []
        assert get_diff_files("HEAD") == []
        assert get_diff_for_file("HEAD", "a.py") == ""
        assert get_file_diff("a.py") == ""

        (tmp_path / "a.py").write_text("x = 2\n")
        _git(tmp_path, "add", "a.py")
        assert get_staged_files() == ["a.py"]
        assert "x = 2" in get_file_diff("a.py")


class TestLspPlumbing:
    class _FakeStdout:
        def __init__(self):
            self.buffer = io.BytesIO()

    class _FakeStdin:
        def __init__(self, data):
            self.buffer = io.BytesIO(data)

    def test_send_and_read_message(self, monkeypatch):
        from prism import lsp

        out = self._FakeStdout()
        monkeypatch.setattr(lsp.sys, "stdout", out)
        lsp._send_message({"jsonrpc": "2.0", "id": 1, "result": None})
        assert b"Content-Length:" in out.buffer.getvalue()

        payload = json.dumps({"jsonrpc": "2.0", "method": "exit"}).encode()
        framed = b"Content-Length: %d\r\n\r\n" % len(payload) + payload
        monkeypatch.setattr(lsp.sys, "stdin", self._FakeStdin(framed))
        assert lsp._read_message()["method"] == "exit"
        assert lsp._read_message() is None

    def test_diagnostics_from_file(self, tmp_path):
        from prism.lsp import _review_file_to_diagnostics

        target = tmp_path / "a.py"
        target.write_text('API_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n')
        diagnostics, error = _review_file_to_diagnostics(str(target), {})
        assert error is None
        assert diagnostics
        assert diagnostics[0]["source"] == "prism"
        assert diagnostics[0]["code"]

    def test_publish_diagnostics_writes_notification(self, monkeypatch):
        from prism import lsp

        out = self._FakeStdout()
        monkeypatch.setattr(lsp.sys, "stdout", out)
        lsp._publish_diagnostics("file:///a.py", [])
        assert b"publishDiagnostics" in out.buffer.getvalue()


class TestRegexAgentRules:
    def test_policy_rules(self, tmp_path):
        from prism.agents_policy import _check_branch_naming, _check_license_header

        licensed = _check_license_header("# SPDX-License-Identifier: MIT\n", "a.py",
                                         ["MIT"])
        assert licensed == []
        missing = _check_license_header("x = 1\n", "a.py", ["MIT"])
        assert missing and missing[0].rule_id == "POL-206"

        assert _check_branch_naming("feature/add-login") == []
        assert _check_branch_naming("add-login") == []
        assert _check_branch_naming("fix/login") == []

    def test_quality_rules(self, tmp_path):
        from prism.agents_quality import (_check_duplication,
                                          _check_imports,
                                          _check_magic_numbers,
                                          _check_missing_docstrings,
                                          _check_missing_type_hints,
                                          _check_naming)

        content = (
            "import os\n"
            "import sys\n"
            "\n"
            "def compute_total(items):\n"
            "    if len(items) > 86400:\n"
            "        return 0\n"
            "    return sum(items)\n"
        )
        assert _check_magic_numbers(content, "a.py")
        assert _check_missing_docstrings(content, "a.py")
        assert _check_missing_type_hints(content, "a.py")
        assert _check_naming(content, "a.py") == []
        assert _check_duplication(content, "a.py") == []
        assert _check_imports("import os\n", "a.py")

    def test_test_agent_rules(self):
        from prism.agents_test import _check_test_naming, _check_weak_assertions

        weak = _check_weak_assertions("def test_x():\n    assert True\n", "test_a.py")
        assert weak and weak[0].rule_id == "TST-104"
        bad_name = _check_test_naming("def check_test_thing():\n    pass\n",
                                      "test_a.py")
        assert bad_name and bad_name[0].rule_id == "TST-105"
        assert _check_test_naming("def test_thing():\n    pass\n", "test_a.py") == []


class TestFindingParsing:
    def test_parse_findings_skips_bad_items(self):
        from prism.ai_findings import parse_findings

        result = {"findings": [
            {"severity": "critical", "message": "eval", "line": 3},
            {"severity": "not-a-severity", "message": "bad"},
        ]}
        findings = parse_findings(result, "a.py", "ai_security")
        assert len(findings) == 1
        assert findings[0].rule_id.startswith("SECU-AI-")
        assert findings[0].blocker.value == "blocks"

    def test_parse_findings_coerces_line_and_confidence(self):
        from prism.ai_findings import parse_findings

        result = {"findings": [
            {"severity": "low", "message": "style", "line": "7",
             "confidence": "not-a-number"},
        ]}
        findings = parse_findings(result, "a.py", "ai_quality")
        assert findings[0].line == 7
        assert findings[0].confidence == 0.85