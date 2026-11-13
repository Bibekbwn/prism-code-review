"""Regression tests for the defects found in the full-system audit.

Each test maps to a specific P0/P1/finding and would have caught it.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from prism.agents import AgentResult, Finding, Severity, Blocker, quality_gates_met
from prism.agents_security import SecurityAgent
from prism.autofix import apply_fixes, _classify_fix
from prism.cli_commands import _findings_to_agent_results
from prism.cli_review import dedupe_results, format_report, review_file


def _finding(agent="security", severity=Severity.CRITICAL, category="Secret Exposure",
             message="Possible api key detected", file="leak.py", line=1,
             rule_id="SECU-101", confidence=0.85):
    return Finding(agent=agent, severity=severity, category=category,
                   message=message, file=file, line=line, rule_id=rule_id,
                   confidence=confidence)


class TestCacheBlocking:
    def test_cached_findings_still_block(self):
        """Cached findings must reach format_report, not just the report file."""
        cached = [{
            "agent": "security", "severity": "critical",
            "category": "Secret Exposure", "problem": "Possible api key detected",
            "file": "leak.py", "line": 1, "suggestion": "Use env vars",
            "suggested_code": None, "confidence": 0.85, "rule_id": "SECU-101",
        }]
        results = _findings_to_agent_results(cached)
        config = {"block_on": ["critical", "high"], "confidence_threshold": 0.7}
        report, blocking = format_report(results, config, {"leak.py": 0.0})
        assert blocking == 1
        assert "COMMIT BLOCKED" in report


class TestDedup:
    def test_ai_findings_collapse_per_line(self):
        f1 = _finding(agent="ai_security", category="Secret Exposure")
        f2 = _finding(agent="ai_quality", category="Hardcoded Secret",
                      message="AWS key hardcoded")
        f3 = _finding(agent="security", category="Secret Exposure")
        results = [AgentResult("ai_security", [f1]),
                   AgentResult("ai_quality", [f2]),
                   AgentResult("security", [f3])]
        cleaned = dedupe_results(results)
        agents = {r.agent_name: len(r.findings) for r in cleaned}
        assert agents.get("ai_security") == 1
        assert "ai_quality" not in agents  # duplicate collapsed
        assert agents.get("security") == 1  # regex kept


class TestAutoFix:
    def test_classify_uses_word_boundaries(self):
        eval_finding = _finding(message="evaluation of results", rule_id="")
        assert _classify_fix(eval_finding) != "remove_eval"
        key_finding = _finding(message="keyword arguments", rule_id="")
        assert _classify_fix(key_finding) != "replace_secret"
        secret_finding = _finding(message="Possible api key detected",
                                  rule_id="SECU-101")
        assert _classify_fix(secret_finding) == "replace_secret"

    def test_secret_fix_adds_os_import(self):
        f = _finding(file="x.py", line=1, rule_id="SECU-101")
        fixed = apply_fixes([(f, 'PASSWORD = os.getenv("PASSWORD")')],
                            'PASSWORD = "hunter2"\n')
        assert "import os" in fixed
        compile(fixed, "x.py", "exec")  # must be syntactically valid

    def test_print_fix_adds_logging_import(self):
        f = _finding(agent="policy", severity=Severity.LOW,
                     category="Banned Pattern",
                     message="Use logging module instead of print()",
                     file="x.py", line=1, rule_id="POL-202")
        fixed = apply_fixes([(f, 'logging.info("hi")')], 'print("hi")\n')
        assert "import logging" in fixed
        compile(fixed, "x.py", "exec")


class TestDotenvSecrets:
    def test_unquoted_password_detected(self):
        findings = SecurityAgent()._check("settings.env", "PASSWORD=hunter2\n", "")
        assert any(f.rule_id == "SECU-123" for f in findings)

    def test_prefixed_key_detected(self):
        findings = SecurityAgent()._check(
            "settings.env", "GEMINI_API_KEY=abcdefghijklmnop\n", "")
        assert any(f.rule_id == "SECU-123" for f in findings)


class TestBinaryAndGates:
    def test_binary_file_skipped(self, tmp_path):
        p = tmp_path / "blob.bin"
        p.write_bytes(b"\x00\x01\x02" * 10)
        results, score = review_file(str(p), {"agents": []}, effort="lite")
        assert results == []
        assert score == 0.0

    def test_min_coverage_zero_is_disabled(self):
        from prism.agents import Blocker

        # A HIGH finding that WARNs (not a blocking one) exercises the
        # min_coverage gate itself; the blocking-finding check must not fire.
        f = _finding(agent="test", severity=Severity.HIGH,
                     category="Missing Tests", rule_id="TST-101")
        f.blocker = Blocker.WARNS
        results = [AgentResult("test", [f])]
        assert quality_gates_met(results, {"quality_gates": {"min_coverage": 0}})
        assert not quality_gates_met(results, {"quality_gates": {"min_coverage": 80}})

    def test_advisory_severity_never_blocks_gates(self):
        # A MEDIUM advisory finding (e.g. missing tests) must not fail the
        # commit gate: only high/critical findings block.
        f = _finding(agent="test", severity=Severity.MEDIUM,
                     category="Missing Tests", rule_id="TST-101")
        results = [AgentResult("test", [f])]
        assert quality_gates_met(
            results, {"quality_gates": {"min_coverage": 80}})


class TestFastSummarize:
    def test_summary_receives_the_prompt(self):
        """--fast used to summarize empty content because the prompt was dropped."""
        from prism.ai_pipeline import _summarize_chunks

        seen = {}

        # Signature must match the real call site; unused names are prefixed
        # with _ to mark them as deliberate positional placeholders.
        def fake_call(model, _system, file_path, content, agent, skeleton,
                      timeout, _cross_file):
            seen["content"] = content
            return {"summary": "chunk summary"}

        out = _summarize_chunks(object(), [(1, "def a():\n    pass\n")],
                                "x.py", "", 10, fake_call, "gemini")
        assert "def a()" in seen["content"]
        assert "chunk summary" in out


class TestCheckStagedJson:
    @pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
    def test_check_staged_stdout_is_pure_json(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)}

        def git(*args):
            return subprocess.run(["git", *args], cwd=str(repo), env=env,
                                  capture_output=True, text=True)

        git("init", "-q")
        git("config", "user.email", "a@b.c")
        git("config", "user.name", "A")
        (repo / "leak.py").write_text(
            'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n')
        git("add", "leak.py")

        proc = subprocess.run(
            [sys.executable, "-m", "prism.cli", "check-staged",
             "--effort", "lite", "--json"],
            cwd=str(repo), env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=300,
        )
        data = json.loads(proc.stdout)  # raises if the output is polluted
        assert proc.returncode == 1
        assert data["commit_allowed"] is False
        assert data["blocking"] >= 1


class TestProviderRetry:
    def _reset(self, monkeypatch):
        import prism.ai_providers as ap
        monkeypatch.setattr(ap.time, "sleep", lambda _s: None)
        monkeypatch.setattr(ap, "_circuit_failures", 0)
        monkeypatch.setattr(ap, "_circuit_open_until", 0.0)
        return ap

    def test_parse_json_from_noisy_text(self):
        import prism.ai_providers as ap
        out = ap._parse_json_response(
            'Here you go:\n```json\n{"findings": [1, 2,], "summary": "x"}\n```\nThanks')
        assert out == {"findings": [1, 2], "summary": "x"}

    def test_invalid_json_is_retried(self, monkeypatch):
        ap = self._reset(monkeypatch)
        calls = {"n": 0}

        def fake(_prompt):
            calls["n"] += 1
            if calls["n"] == 1:
                return "not json at all"
            return '{"findings": [], "summary": "ok"}'

        out = ap._call_with_retry(fake, "prompt", "ai_test", 10)
        assert calls["n"] == 2
        assert out.get("_failed") is None

    def test_permanent_failure_is_reported(self, monkeypatch):
        ap = self._reset(monkeypatch)
        out = ap._call_with_retry(lambda _p: "still not json", "prompt",
                                  "ai_test", 10)
        assert out["_failed"] is True
        assert "valid JSON" in out["_error"]

    def test_backoff_stays_inside_retry_budget(self, monkeypatch):
        ap = self._reset(monkeypatch)
        deadline = ap.time.monotonic() + 1.0

        for attempt in range(4):
            delay = ap._retry_delay(attempt, deadline)
            assert 0.0 <= delay <= 1.0

        assert ap._retry_delay(0, ap.time.monotonic() - 1) == 0.0

    def test_flaky_call_costs_well_under_a_second_of_sleep(self, monkeypatch):
        ap = self._reset(monkeypatch)
        calls = {"n": 0}

        def fake(_prompt):
            calls["n"] += 1
            if calls["n"] == 1:
                return "not json at all"
            return '{"findings": [], "summary": "ok"}'

        out = ap._call_with_retry(fake, "prompt", "ai_test", 10)
        assert calls["n"] == 2
        assert out.get("_failed") is None
        assert ap.RETRY_BASE_DELAY + ap.RETRY_BASE_DELAY * 2 < 1.0


class TestAutoFixDangerousCalls:
    def _finding(self, rule_id, message, line):
        return _finding(agent="security", severity=Severity.HIGH,
                        category="Dangerous Pattern", message=message,
                        file="x.py", line=line, rule_id=rule_id)

    def test_return_eval_becomes_return_none(self):
        from prism.autofix import generate_fix
        f = self._finding("SECU-201", "Use of eval()", 2)
        fixed = generate_fix(f, "def f(x):\n    return eval(x)\n")
        assert "return None" in fixed
        compile("def f(x):\n" + fixed + "\n", "x.py", "exec")

    def test_assignment_eval_becomes_none(self):
        from prism.autofix import generate_fix
        f = self._finding("SECU-201", "Use of eval()", 1)
        fixed = generate_fix(f, "x = eval(y)\n")
        assert "x = None" in fixed
        compile(fixed, "x.py", "exec")

    def test_exec_statement_becomes_pass(self):
        from prism.autofix import generate_fix
        f = self._finding("SECU-202", "Use of exec()", 1)
        fixed = generate_fix(f, 'exec("print(1)")\n')
        assert "pass" in fixed
        compile(fixed, "x.py", "exec")


class TestAutoFixCompileGuard:
    def _finding(self, line, rule_id="SECU-201"):
        return _finding(agent="security", severity=Severity.HIGH,
                        category="Dangerous Pattern", message="Use of eval()",
                        file="x.py", line=line, rule_id=rule_id)

    def test_broken_generated_code_is_rejected(self):
        from prism.autofix import apply_fixes

        content = "def f():\n    return 1\n"
        broken = apply_fixes([(self._finding(2), "    return (")], content)
        assert broken == content

    def test_eval_fix_keeps_file_parsable(self):
        from prism.autofix import apply_fixes

        content = "def f(x):\n    return eval(x)\n"
        fixed = apply_fixes([(self._finding(2), "    return None")], content)
        assert "return None" in fixed
        compile(fixed, "x.py", "exec")

    def test_secret_fix_adds_import_and_compiles(self):
        from prism.autofix import apply_fixes

        content = 'API_KEY = "sk-live-123"\n'
        finding = _finding(agent="security", severity=Severity.HIGH,
                           category="Secret Exposure",
                           message="Hardcoded api key", file="x.py", line=1,
                           rule_id="SECU-101")
        fixed = apply_fixes(
            [(finding, 'API_KEY = os.getenv("API_KEY")')], content)
        assert "import os" in fixed
        compile(fixed, "x.py", "exec")


class TestDedupDistinctIssues:
    def test_same_category_family_collapses(self):
        f1 = _finding(agent="ai_security", category="Secret Exposure",
                      message="Hardcoded AWS access key", line=3)
        f2 = _finding(agent="ai_quality", category="Hardcoded Secret",
                      message="Possible aws access key id detected", line=3)
        cleaned = dedupe_results([AgentResult("ai_security", [f1]),
                                  AgentResult("ai_quality", [f2])])
        assert len(cleaned) == 1

    def test_different_family_same_line_is_kept(self):
        f1 = _finding(agent="ai_security", category="Secret Exposure",
                      message="Hardcoded AWS key", line=3)
        f2 = _finding(agent="ai_performance", category="Performance",
                      message="Nested loop O(n^2)", line=3)
        cleaned = dedupe_results([AgentResult("ai_security", [f1]),
                                  AgentResult("ai_performance", [f2])])
        assert len(cleaned) == 2

    def test_two_distinct_secrets_on_one_line_are_kept(self):
        f1 = _finding(agent="ai_security", category="Secret Exposure",
                      message="Hardcoded AWS access key", line=4)
        f2 = _finding(agent="ai_quality", category="Secret Exposure",
                      message="Hardcoded database password", line=4)
        cleaned = dedupe_results([AgentResult("ai_security", [f1]),
                                  AgentResult("ai_quality", [f2])])
        assert len(cleaned) == 2


class TestImportGraph:
    def test_relative_and_absolute_imports(self, tmp_path):
        from prism.ai_graph import build_import_graph, invalidate_graph_cache

        invalidate_graph_cache()
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helper.py").write_text("def help():\n    return 1\n")
        (pkg / "mod.py").write_text(
            "from .helper import help\n\n\ndef run():\n    return help()\n")
        (pkg / "abs.py").write_text("import pkg.helper\n")

        graph = build_import_graph(tmp_path)
        helper = next(v for k, v in graph.items() if k.endswith("helper.py"))
        imported_by = {Path(p).name for p in helper["imported_by"]}
        assert "mod.py" in imported_by
        assert "abs.py" in imported_by
        invalidate_graph_cache()

    def test_no_self_import_edges(self, tmp_path):
        from prism.ai_graph import build_import_graph, invalidate_graph_cache

        invalidate_graph_cache()
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "mod.py").write_text(
            "from pkg.mod import thing\n\n\ndef run():\n    return thing()\n")

        graph = build_import_graph(tmp_path)
        mod = next(v for k, v in graph.items() if k.endswith("mod.py"))
        assert mod["imported_by"] == []
        invalidate_graph_cache()

    def test_resolution_is_linear_not_quadratic(self, tmp_path):
        from prism.ai_graph import build_import_graph, invalidate_graph_cache

        invalidate_graph_cache()
        target = tmp_path / "target.py"
        target.write_text("def target():\n    return 1\n")
        importers = []
        for i in range(60):
            name = "importer_%02d.py" % i
            (tmp_path / name).write_text("from target import target\n")
            importers.append(name)

        graph = build_import_graph(tmp_path)
        target_info = next(v for k, v in graph.items() if k.endswith("target.py"))
        assert {Path(p).name for p in target_info["imported_by"]} == set(importers)
        assert all(isinstance(p, str) for p in target_info["imported_by"])
        invalidate_graph_cache()

class TestGraphCacheInvalidation:
    def test_graph_reflects_edits_without_manual_invalidation(self, tmp_path):
        from prism.ai_graph import build_import_graph, invalidate_graph_cache

        invalidate_graph_cache()
        target = tmp_path / "mod.py"
        target.write_text("def first():\n    return 1\n")

        graph = build_import_graph(tmp_path)
        funcs = next(v for v in graph.values())["functions"]
        assert "first" in funcs

        target.write_text("def second():\n    return 2\n")
        graph2 = build_import_graph(tmp_path)
        funcs2 = next(v for v in graph2.values())["functions"]
        assert "second" in funcs2
        assert "first" not in funcs2

    def test_unchanged_repo_reuses_cached_graph(self, tmp_path):
        from prism.ai_graph import build_import_graph, invalidate_graph_cache

        invalidate_graph_cache()
        (tmp_path / "mod.py").write_text("def a():\n    return 1\n")
        first = build_import_graph(tmp_path)
        second = build_import_graph(tmp_path)
        assert first is second
        invalidate_graph_cache()


class TestRiskScoreIsFindingAware:
    def test_critical_finding_raises_risk(self):
        from prism.agents import risk_score, Finding, Severity

        quiet = risk_score("tiny.py", "x = 1\n", "x = 1\n", [])
        assert quiet == 0.0

        f = Finding(agent="security", severity=Severity.CRITICAL,
                    category="Dangerous Pattern", message="eval()",
                    file="tiny.py", line=1, confidence=1.0, rule_id="SECU-201")
        assert risk_score("tiny.py", "x = 1\n", "x = 1\n", [f]) >= 0.25


class TestQualityGateSemantics:
    def test_blocking_finding_fails_gate(self):
        from prism.agents import AgentResult

        f = Finding(agent="security", severity=Severity.HIGH,
                    category="Dangerous Pattern", message="eval()",
                    file="x.py", line=1, blocker=Blocker.BLOCKS,
                    confidence=1.0, rule_id="SECU-201")
        results = [AgentResult("security", [f], passed=False)]
        assert quality_gates_met(results, {"block_on": ["critical", "high"]}) is False

    def test_non_blocking_finding_passes_gate(self):
        from prism.agents import AgentResult

        f = Finding(agent="style", severity=Severity.LOW,
                    category="Style", message="naming",
                    file="x.py", line=1, blocker=Blocker.ALLOWS,
                    confidence=1.0, rule_id="POL-101")
        results = [AgentResult("style", [f], passed=True)]
        assert quality_gates_met(results, {"block_on": ["critical", "high"]}) is True


class TestAiErrorSeverity:
    def test_provider_outage_is_blocking(self):
        from prism.ai_pipeline import _error_finding
        from prism.agents import Blocker, Severity

        f = _error_finding("ai_security", "x.py", "504 Deadline expired",
                           blocking=True)
        assert f.severity == Severity.HIGH
        assert f.blocker == Blocker.BLOCKS

    def test_missing_key_is_not_an_outage(self):
        from prism.ai_pipeline import _error_finding
        from prism.agents import Blocker, Severity

        f = _error_finding("ai_security", "x.py", "no API key configured")
        assert f.severity == Severity.LOW
        assert f.blocker == Blocker.ALLOWS


class TestProviderHardTimeout:
    def test_hung_call_is_abandoned(self):
        import time as _time
        import prism.ai_providers as ap

        def _hang():
            _time.sleep(0.8)
            return "{}"

        start = _time.monotonic()
        with pytest.raises(TimeoutError):
            ap._invoke_with_deadline(_hang, None, 0.05)
        assert _time.monotonic() - start < 0.7


class TestFixPreviewAndBackup:
    def test_non_interactive_fix_is_not_applied(self, tmp_path, monkeypatch):
        from prism.cli_commands import _apply_fixes_with_preview
        from prism.agents import Finding, Severity

        target = tmp_path / "dirty.py"
        content = "eval('1')\n"
        target.write_text(content)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        finding = Finding(agent="security", severity=Severity.HIGH,
                          category="Dangerous Pattern", message="eval()",
                          file=str(target), line=1, confidence=1.0,
                          rule_id="SECU-201")
        applied = _apply_fixes_with_preview(target, content, [(finding, "pass")])
        assert applied is False
        assert target.read_text() == content
        assert not (tmp_path / "dirty.py.prism-bak").exists()

    def test_confirmed_fix_writes_file_and_backup(self, tmp_path):
        from prism.cli_commands import _apply_fixes_with_preview
        from prism.agents import Finding, Severity

        target = tmp_path / "dirty.py"
        content = "eval('1')\n"
        target.write_text(content)
        finding = Finding(agent="security", severity=Severity.HIGH,
                          category="Dangerous Pattern", message="eval()",
                          file=str(target), line=1, confidence=1.0,
                          rule_id="SECU-201")

        applied = _apply_fixes_with_preview(target, content, [(finding, "pass")],
                                            assume_yes=True)
        assert applied is True
        assert target.read_text() == "pass\n"
        assert (tmp_path / "dirty.py.prism-bak").read_text() == content


class TestDedupQualifierEdge:
    def test_aws_key_and_ssh_key_on_one_line_are_kept(self):
        f1 = _finding(agent="ai_security", category="Secret Exposure",
                      message="Hardcoded AWS key", line=5)
        f2 = _finding(agent="ai_quality", category="Secret Exposure",
                      message="Hardcoded SSH key", line=5)
        cleaned = dedupe_results([AgentResult("ai_security", [f1]),
                                  AgentResult("ai_quality", [f2])])
        assert len(cleaned) == 2


class TestHookWiring:
    def test_hook_script_runs_check_staged_without_json(self):
        script = Path(__file__).parent.parent / "prism" / "pre-commit-hook.sh"
        text = script.read_text(encoding="utf-8", errors="ignore")
        assert "check-staged" in text
        assert "check-staged --prompt --json" not in text

    def test_install_hook_refuses_outside_git(self, tmp_path, monkeypatch):
        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit):
            cc._cmd_install_hook(None)


class TestAgentToggle:
    def test_disable_uses_dict_config(self, tmp_path, monkeypatch):
        import argparse
        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        (tmp_path / "prism.json").write_text(json.dumps(
            {"agents": {"security": True, "ai_test": True}}))

        cc._cmd_agents(argparse.Namespace(enable=None, disable="ai_test"))
        config = json.loads((tmp_path / "prism.json").read_text())
        assert config["agents"]["ai_test"] is False
        assert config["agents"]["security"] is True

    def test_enable_unknown_agent_is_reported(self, tmp_path, monkeypatch, capsys):
        import argparse
        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        (tmp_path / "prism.json").write_text(json.dumps({"agents": {"security": True}}))
        cc._cmd_agents(argparse.Namespace(enable=None, disable="nope"))
        assert "Agent not found: nope" in capsys.readouterr().out

    def test_list_config_shape_is_supported(self, tmp_path, monkeypatch):
        import argparse
        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        (tmp_path / "prism.json").write_text(json.dumps({"agents": ["security"]}))
        cc._cmd_agents(argparse.Namespace(enable=None, disable="security"))
        assert json.loads((tmp_path / "prism.json").read_text())["agents"] == []


class TestCachedRiskScore:
    def test_cached_findings_keep_their_risk(self):
        from prism.cli_commands import _cached_risk_score

        cached = [{
            "agent": "security", "severity": "critical",
            "category": "Dangerous Pattern", "problem": "eval()",
            "file": "x.py", "line": 1, "suggestion": "", "suggested_code": None,
            "confidence": 1.0, "rule_id": "SECU-201",
        }]
        score = _cached_risk_score("x.py", cached)
        assert score > 0.0


class TestKeySetValidation:
    def test_placeholder_key_is_rejected(self, tmp_path, monkeypatch, capsys):
        import argparse
        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        args = argparse.Namespace(action="set", provider="gemini",
                                  key="your-api-key-here")
        with pytest.raises(SystemExit):
            cc._cmd_key(args)
        assert "placeholder" in capsys.readouterr().out.lower()
        assert not (tmp_path / ".env").exists()
        assert not (tmp_path / ".config" / ".env").exists()


class TestSecretRuleGaps:
    def _scan(self, tmp_path, source):
        from prism.agents_security import SecurityAgent

        target = tmp_path / "leak.py"
        target.write_text(source)
        result = SecurityAgent().review(str(target), source, "")
        return [f.rule_id for f in result.findings]

    def test_prefixed_password_is_detected(self, tmp_path):
        ids = self._scan(tmp_path, 'DB_PASSWORD = "sup3r-s3cret"\n')
        assert "SECU-103" in ids

    def test_session_key_is_detected(self, tmp_path):
        ids = self._scan(tmp_path, 'SESSION_KEY = "django-insecure-demo-key"\n')
        assert "SECU-102" in ids

    def test_short_live_stripe_key_is_detected(self, tmp_path):
        ids = self._scan(tmp_path, 'STRIPE_SECRET = "sk_live_51H8xQ2eZvKYlo2C"\n')
        assert "SECU-111" in ids


class TestCliErrorSurfaces:
    def test_missing_file_json_is_still_json(self, tmp_path):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        proc = subprocess.run(
            [sys.executable, "-m", "prism.cli", "check", "nope.py", "--json"],
            cwd=str(tmp_path), capture_output=True, text=True, env=env)
        assert proc.returncode == 2
        payload = json.loads(proc.stdout)
        assert payload["error"].startswith("File not found")
        assert payload["blocking"] == 0

    def test_unknown_report_id_exits_nonzero(self, tmp_path):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        (tmp_path / ".prism-reports").mkdir()
        proc = subprocess.run(
            [sys.executable, "-m", "prism.cli", "report", "bogus-id"],
            cwd=str(tmp_path), capture_output=True, text=True, env=env)
        assert proc.returncode == 1


class TestEnvLoading:
    def test_load_env_reads_cwd_dotenv(self, tmp_path, monkeypatch):
        import prism

        (tmp_path / ".env").write_text("GEMINI_API_KEY=unit-test-key-value\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(prism, "_ENV_LOADED", False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

        prism.load_env()
        assert os.getenv("GEMINI_API_KEY") == "unit-test-key-value"


class TestFailedMessageSeverity:
    def test_invalid_json_is_not_blocking(self):
        from prism.ai_pipeline import _failed_message

        message, blocking = _failed_message(
            {"_failed": True, "_error_kind": "invalid_json",
             "_error": "API error after 2 attempt(s): model did not return valid JSON"})
        assert "valid JSON" in message
        assert blocking is False

    def test_transport_failure_is_blocking(self):
        from prism.ai_pipeline import _failed_message

        message, blocking = _failed_message(
            {"_failed": True, "_error_kind": "transport",
             "_error": "API error after 2 attempt(s): 504 Deadline expired"})
        assert "504" in message
        assert blocking is True

    def test_unknown_kind_defaults_to_blocking(self):
        from prism.ai_pipeline import _failed_message

        _message, blocking = _failed_message({"_failed": True, "_error": "boom"})
        assert blocking is True


class TestDashboardAutoOpen:
    """The HTML dashboard must open by itself after a review."""

    def test_build_dashboard_writes_html_and_returns_path(self, tmp_path, monkeypatch):
        from prism.commands_reports import build_dashboard

        monkeypatch.chdir(tmp_path)
        path = build_dashboard(open_browser=False)
        assert path is not None
        generated = Path(path)
        assert generated.exists()
        html = generated.read_text(encoding="utf-8", errors="ignore")
        assert "EMBEDDED_REPORTS" in html

    def test_build_dashboard_opens_browser_when_requested(self, tmp_path, monkeypatch):
        import prism.commands_reports as cr

        monkeypatch.chdir(tmp_path)
        opened = []
        monkeypatch.setattr(cr, "open_dashboard",
                            lambda url: opened.append(url) or True)

        cr.build_dashboard(open_browser=True)
        assert opened and opened[0].startswith("file:///")

    def test_dashboard_cmd_opens_browser(self, tmp_path, monkeypatch):
        import argparse
        import prism.commands_reports as cr

        monkeypatch.chdir(tmp_path)
        opened = []
        monkeypatch.setattr(cr, "open_dashboard",
                            lambda url: opened.append(url) or True)

        cr._cmd_dashboard(argparse.Namespace())
        assert opened and opened[0].startswith("file:///")

    def test_dashboard_disabled_by_flag(self, monkeypatch):
        import argparse
        from prism.commands_common import _dashboard_enabled

        assert _dashboard_enabled(argparse.Namespace(no_dashboard=True)) is False

    def test_dashboard_disabled_in_ci(self, monkeypatch):
        import argparse
        from prism.commands_common import _dashboard_enabled

        monkeypatch.setenv("CI", "true")
        monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
        assert _dashboard_enabled(argparse.Namespace()) is False

    def test_dashboard_disabled_when_not_a_tty(self, monkeypatch):
        import argparse
        from prism.commands_common import _dashboard_enabled

        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: False, raising=False)
        assert _dashboard_enabled(argparse.Namespace()) is False

    def test_dashboard_enabled_on_interactive_terminal(self, monkeypatch):
        import argparse
        from prism.commands_common import _dashboard_enabled

        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("PRISM_NO_DASHBOARD", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
        assert _dashboard_enabled(argparse.Namespace()) is True


class TestDeadCodeRemoved:
    """Guards against the dead code the audit found creeping back in."""

    def test_no_dangling_regex_assignment(self):
        import ast

        source = Path("prism/agents_quality.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        assigned = {
            node.id
            for stmt in ast.walk(tree)
            if isinstance(stmt, ast.Assign)
            for node in stmt.targets
            if isinstance(node, ast.Name)
        }
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        assert "assignment_rhs" not in assigned - used

    def test_cross_file_context_has_no_dead_parameter(self):
        import inspect

        from prism.ai_graph import get_cross_file_context

        assert "max_depth" not in inspect.signature(
            get_cross_file_context).parameters

    def test_ai_common_does_not_export_dead_wrapper(self):
        import prism.ai_common as ac

        assert not hasattr(ac, "call_fn")

    def test_lsp_imports_agents_from_their_modules(self):
        """lsp must not import review_file/load_config from prism.cli (it
        used to, and broke when cli.py stopped re-exporting them)."""
        source = Path("prism/lsp.py").read_text(encoding="utf-8")
        assert "from prism.cli import" not in source


class TestIgnorePatterns:
    """The developer-controlled pre-commit exclusion list."""

    def test_readme_and_docs_are_skipped_by_default(self):
        from prism.ignore import is_ignored

        assert is_ignored("README.md")
        assert is_ignored("docs/guide.md")
        assert is_ignored("CHANGELOG.md")

    def test_source_files_are_reviewed(self):
        from prism.ignore import is_ignored

        assert not is_ignored("prism/cli.py")
        assert not is_ignored("src/main.py")

    def test_assets_and_lockfiles_are_skipped(self):
        from prism.ignore import is_ignored

        assert is_ignored("logo.png")
        assert is_ignored("package-lock.json")
        assert is_ignored("yarn.lock")

    def test_folder_pattern_skips_children(self):
        from prism.ignore import is_ignored

        assert is_ignored("vendor/pkg/mod.py", ["vendor/"])
        assert not is_ignored("src/vendor.py", ["vendor/"])

    def test_folder_pattern_matches_at_any_depth(self):
        """`__pycache__/` must skip nested caches, not just a root-level one."""
        from prism.ignore import is_ignored

        assert is_ignored("pkg/__pycache__/mod.pyc", ["__pycache__/"])
        assert is_ignored("a/b/__pycache__/mod.pyc", ["__pycache__/"])
        assert not is_ignored("pkg/__pycache___notes.py", ["__pycache__/"])

    def test_dotfolders_are_not_stripped(self):
        """`.vscode/` must not be turned into `vscode/` by lstrip('.')."""
        from prism.ignore import is_ignored

        assert is_ignored(".vscode/settings.json", [".vscode/"])
        assert is_ignored(".idea/workspace.xml", [".idea/"])
        assert not is_ignored("vscode/settings.json", [".vscode/"])

    def test_build_output_and_deps_skipped(self):
        from prism.ignore import is_ignored

        for path in ("dist/bundle.js", "build/lib/mod.py",
                     "node_modules/pkg/index.js", "poetry.lock",
                     "coverage/lcov.info"):
            assert is_ignored(path), path

    def test_dotfiles_that_matter_still_reviewed(self):
        """Ignoring repo metadata must not hide real source or config."""
        from prism.ignore import is_ignored

        assert not is_ignored("Dockerfile")
        assert not is_ignored("docker-compose.yml")
        assert not is_ignored("prism.json")
        assert not is_ignored("src/app.py")

    def test_certificates_and_data_skipped(self):
        from prism.ignore import is_ignored

        for path in ("certs/server.pem", "keystore.p12", "dump.sql",
                     "data/export.csv", "assets/logo.png"):
            assert is_ignored(path), path

    def test_starter_list_is_readable_subset_of_defaults(self):
        """`prism ignore reset` writes a short, editable list."""
        from prism.ignore import STARTER_IGNORE, is_ignored

        assert len(STARTER_IGNORE) <= 30
        for pattern in STARTER_IGNORE:
            assert is_ignored(pattern.rstrip("/") + "/x.py", [pattern]) or \
                is_ignored(pattern, [pattern]) or pattern.endswith("/"), pattern

    def test_negation_reincludes(self):
        from prism.ignore import is_ignored

        patterns = ["*.md", "!keep.md"]
        assert is_ignored("README.md", patterns)
        assert not is_ignored("keep.md", patterns)

    def test_matching_is_case_insensitive(self):
        from prism.ignore import is_ignored

        assert is_ignored("LOGO.PNG")
        assert is_ignored("readme.MD")

    def test_filter_files_splits_review_from_skipped(self):
        from prism.ignore import filter_files

        files = ["README.md", "app.py", "logo.png"]
        kept, skipped = filter_files(files)
        assert kept == ["app.py"]
        assert skipped == ["README.md", "logo.png"]

    def test_add_then_remove_round_trip(self, tmp_path, monkeypatch):
        import prism.ignore as ig

        monkeypatch.chdir(tmp_path)
        assert ig.add_patterns(["secrets/"]) == ["secrets/"]
        assert "secrets/" in ig.read_ignore_file()
        # Adding twice does not duplicate
        assert ig.add_patterns(["secrets/"]) == []
        assert ig.remove_patterns(["secrets/"]) == ["secrets/"]
        assert "secrets/" not in ig.read_ignore_file()

    def test_add_rejects_builtin_defaults(self, tmp_path, monkeypatch):
        import prism.ignore as ig

        monkeypatch.chdir(tmp_path)
        assert ig.add_patterns(["*.md"]) == []

    def test_ignore_file_skips_comments_and_blanks(self, tmp_path, monkeypatch):
        import prism.ignore as ig

        monkeypatch.chdir(tmp_path)
        (tmp_path / ig.IGNORE_FILE).write_text(
            "# a comment\n\n  \nsecrets/\n!keep.py\n")
        assert ig.read_ignore_file() == ["secrets/", "!keep.py"]

    def test_get_staged_files_honours_ignore(self, tmp_path, monkeypatch):
        import subprocess

        import prism.cli_config as cc

        def _git(*args):
            subprocess.run(["git"] + list(args), cwd=str(tmp_path),
                           check=True, capture_output=True)

        _git("init")
        _git("config", "user.email", "t@t.t")
        _git("config", "user.name", "t")
        (tmp_path / "README.md").write_text("docs")
        (tmp_path / "app.py").write_text("x = 1\n")
        _git("add", "-A")
        _git("commit", "-m", "init")

        (tmp_path / "README.md").write_text("docs changed")
        (tmp_path / "app.py").write_text("x = 2\n")
        _git("add", "-A")

        monkeypatch.chdir(tmp_path)
        files = cc.get_staged_files()
        assert files == ["app.py"]

        # apply_ignore=False returns everything, for `prism ignore list`
        raw = cc.get_staged_files(apply_ignore=False)
        assert sorted(raw) == ["README.md", "app.py"]


class TestDashboardRendering:
    """The generated dashboard must actually contain the report data."""

    def test_generated_html_defines_embedded_reports(self, tmp_path, monkeypatch):
        from prism.commands_reports import build_dashboard

        monkeypatch.chdir(tmp_path)
        path = build_dashboard(open_browser=False)
        html = Path(path).read_text(encoding="utf-8", errors="ignore")
        assert "const EMBEDDED_REPORTS = [" in html
        assert "/* PRISM_DASHBOARD_DATA */" not in html

    def test_generated_html_calls_load_reports(self, tmp_path, monkeypatch):
        from prism.commands_reports import build_dashboard

        monkeypatch.chdir(tmp_path)
        path = build_dashboard(open_browser=False)
        html = Path(path).read_text(encoding="utf-8", errors="ignore")
        assert "loadReports();" in html

    def test_embedded_data_is_valid_json(self, tmp_path, monkeypatch):
        import json
        import re

        from prism.commands_reports import build_dashboard

        monkeypatch.chdir(tmp_path)
        path = build_dashboard(open_browser=False)
        html = Path(path).read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"const EMBEDDED_REPORTS = (\[.*?\]);", html,
                          re.DOTALL)
        assert match, "no EMBEDDED_REPORTS assignment found"
        assert isinstance(json.loads(match.group(1)), list)

    def test_reports_written_by_review_appear_in_dashboard(self, tmp_path, monkeypatch):
        """The dashboard must show reports produced by a real review."""
        from prism.cli_review import review_file
        from prism.commands_reports import build_dashboard
        from prism.reports import save_report

        monkeypatch.chdir(tmp_path)
        src = tmp_path / "app.py"
        src.write_text("import os\nx = 1\n")
        results, score = review_file(str(src), {}, "lite")
        findings = [f for r in results for f in r.findings]
        save_report(
            files_reviewed=["app.py"],
            findings=[{
                "agent": f.agent, "severity": f.severity.value,
                "category": f.category, "problem": f.message,
                "file": f.file, "line": f.line,
            } for f in findings],
            risk_score=score, blocking=len(findings), commit_allowed=True,
        )

        path = build_dashboard(open_browser=False)
        html = Path(path).read_text(encoding="utf-8", errors="ignore")
        assert '"files_reviewed": ["app.py"]' in html or "app.py" in html
        assert "EMBEDDED_REPORTS" in html


class TestAgentModes:
    """`prism mode` must let a developer turn off regex and/or AI agents."""

    def test_default_mode_is_all(self):
        from prism.modes import MODE_ALL, get_mode

        assert get_mode({}) == MODE_ALL

    def test_regex_mode_drops_ai_agents(self):
        from prism.modes import MODE_REGEX, select_agents

        agents = ["security", "ai_security", "quality", "ai_quality"]
        assert select_agents(agents, MODE_REGEX) == ["security", "quality"]

    def test_none_mode_drops_everything(self):
        from prism.modes import MODE_NONE, select_agents

        agents = ["security", "ai_security"]
        assert select_agents(agents, MODE_NONE) == []

    def test_none_mode_is_not_overridden_by_max_effort(self):
        from prism.modes import MODE_NONE, select_agents

        assert select_agents(["security"], MODE_NONE, "max") == []

    def test_lite_effort_still_filters_in_all_mode(self):
        from prism.modes import MODE_ALL, select_agents

        agents = ["security", "ai_security"]
        assert select_agents(agents, MODE_ALL, "lite") == ["security"]

    def test_set_mode_persists_to_prism_json(self, tmp_path, monkeypatch):
        import json

        import prism.modes as modes

        monkeypatch.chdir(tmp_path)
        (tmp_path / "prism.json").write_text(json.dumps({"agents": ["security"]}))
        assert modes.set_mode("regex") == "regex"
        assert json.loads((tmp_path / "prism.json").read_text())["mode"] == "regex"
        assert modes.get_mode() == "regex"

    def test_set_mode_rejects_unknown(self, tmp_path, monkeypatch):
        import prism.modes as modes

        monkeypatch.chdir(tmp_path)
        assert modes.set_mode("bogus") is None

    def test_get_mode_falls_back_for_garbage(self):
        from prism.modes import MODE_ALL, get_mode

        assert get_mode({"mode": "nonsense"}) == MODE_ALL

    def test_mode_command_lists_current(self, tmp_path, monkeypatch, capsys):
        import argparse

        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        cc._cmd_mode(argparse.Namespace(mode=None))
        out = capsys.readouterr().out
        assert "Mode: all" in out
        assert "regex" in out and "none" in out

    def test_mode_command_sets_and_reports(self, tmp_path, monkeypatch, capsys):
        import argparse
        import json

        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        cc._cmd_mode(argparse.Namespace(mode="regex"))
        assert json.loads((tmp_path / "prism.json").read_text())["mode"] == "regex"
        assert "Mode set to regex" in capsys.readouterr().out

    def test_mode_command_rejects_unknown(self, tmp_path, monkeypatch):
        import argparse

        import prism.cli_commands as cc

        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit):
            cc._cmd_mode(argparse.Namespace(mode="bogus"))

    def test_none_mode_still_writes_a_report(self, tmp_path, monkeypatch):
        """`none` must not break the report/dashboard pipeline."""
        from prism.cli_review import review_file

        monkeypatch.chdir(tmp_path)
        src = tmp_path / "app.py"
        src.write_text('API_KEY = "supersecretvalue123"\n')

        config = {"mode": "none", "agents": ["security", "quality"],
                  "policy": {"headers": False}}
        results, score = review_file(str(src), config, "balanced")
        assert results == []
        assert score == 0.0

    def test_regex_mode_skips_ai_agents_in_review(self, tmp_path, monkeypatch):
        from prism.cli_review import review_file

        monkeypatch.chdir(tmp_path)
        src = tmp_path / "app.py"
        src.write_text('API_KEY = "supersecretvalue123"\n')

        config = {"mode": "regex",
                  "agents": ["security", "ai_security"],
                  "policy": {"headers": False}}
        results, _score = review_file(str(src), config, "balanced")
        names = {r.agent_name for r in results}
        assert "ai_security" not in names


class TestAgentModeSelection:
    """select_agents composes mode and the per-invocation effort."""

    AGENTS = ["security", "quality", "ai_security", "ai_quality"]

    def test_all_mode_keeps_everything(self):
        from prism.modes import MODE_ALL, select_agents

        assert select_agents(self.AGENTS, MODE_ALL) == self.AGENTS

    def test_regex_mode_drops_ai_agents(self):
        from prism.modes import MODE_REGEX, select_agents

        assert select_agents(self.AGENTS, MODE_REGEX) == ["security", "quality"]

    def test_none_mode_is_empty(self):
        from prism.modes import MODE_NONE, select_agents

        assert select_agents(self.AGENTS, MODE_NONE) == []

    def test_lite_effort_drops_ai_agents(self):
        from prism.modes import MODE_ALL, select_agents

        assert select_agents(self.AGENTS, MODE_ALL, effort="lite") == [
            "security", "quality"]

    def test_disabled_agent_is_actually_skipped_in_review(self, tmp_path, monkeypatch):
        # `prism agents --disable quality` must stop the agent in a review.
        import importlib

        from prism.cli_review import review_file
        importlib.import_module("prism.agents_quality")
        importlib.import_module("prism.agents_test")

        monkeypatch.chdir(tmp_path)
        src = tmp_path / "app.py"
        src.write_text("def f():\n    return 1\n")

        base = {"mode": "regex", "agents": ["quality", "test"],
                "policy": {"headers": False}}
        before, _ = review_file(str(src), base, "lite")
        after, _ = review_file(
            str(src), {"mode": "regex", "agents": {"quality": False, "test": True},
                       "policy": {"headers": False}}, "lite")

        assert any(r.agent_name == "quality" for r in before)
        assert not any(r.agent_name == "quality" for r in after)
        assert any(r.agent_name == "test" for r in after)
