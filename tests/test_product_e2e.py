"""End-to-end product test: score the reviewer on a known corpus.

Runs the deterministic security agent over a vulnerable file and a clean file,
then runs the AI path with a stubbed provider (so no API key is needed) to
exercise chunking and token accounting. The final score is precision/recall/F1
over the expected vulnerable lines; it must stay high for the tool to be
trustworthy in CI.
"""

import argparse
import json
import sys
from pathlib import Path

import pytest

VULN = '''import hashlib
import subprocess


def run(user_input, data, cmd):
    API_KEY = "sk_live_51H8xQ2abcdef123456"
    eval(user_input)
    subprocess.call(cmd, shell=True)
    return hashlib.md5(data).hexdigest()
'''

CLEAN = '''import os


def add(a, b):
    API_KEY = os.getenv("API_KEY")
    return a + b
'''

# 1-based lines in VULN that must be flagged.
EXPECTED_LINES = {6, 7, 8, 9}


def _review(path, config, effort="lite"):
    from prism.cli_review import review_file
    return review_file(str(path), config, effort, False)


def _score(vuln_findings, clean_findings):
    found = {f.line for f in vuln_findings if f.line in EXPECTED_LINES}
    tp = len(found)
    fn = len(EXPECTED_LINES - found)
    fp = len(clean_findings)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


class TestScoredReview:
    def test_deterministic_precision_recall(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        vuln = tmp_path / "vuln.py"
        clean = tmp_path / "clean.py"
        vuln.write_text(VULN)
        clean.write_text(CLEAN)
        config = {"agents": ["security"], "block_on": ["critical", "high"]}

        vuln_results, _ = _review(vuln, config)
        clean_results, _ = _review(clean, config)
        vuln_findings = [f for r in vuln_results for f in r.findings]
        clean_findings = [f for r in clean_results for f in r.findings]

        score = _score(vuln_findings, clean_findings)
        print("\nSCORE:", json.dumps(score))
        assert score["tp"] >= 4, [f.message for f in vuln_findings]
        assert score["fp"] == 0, [f.message for f in clean_findings]
        assert score["f1"] >= 0.9

    def test_ai_path_records_tokens(self, tmp_path, monkeypatch):
        import prism.ai_pipeline as ap_pipeline
        import prism.ai_providers as ap
        import prism.ai_graph as ag
        from prism import token_usage

        monkeypatch.chdir(tmp_path)
        target = tmp_path / "app.py"
        target.write_text("x = 1\n")

        payload = {"findings": [{
            "severity": "high", "category": "Stub", "message": "stub",
            "file": "app.py", "line": 1, "suggestion": "fix"}], "summary": "ok"}

        class _Usage:
            prompt_token_count = 25
            candidates_token_count = 8

        class _Response:
            text = json.dumps(payload)
            usage_metadata = _Usage()

        class _Model:
            def generate_content(self, *a, **k):
                return _Response()

        monkeypatch.setattr(ag, "build_import_graph", lambda *a, **k: {})
        monkeypatch.setattr(ag, "get_cross_file_context", lambda *a, **k: "")
        monkeypatch.setattr(ap_pipeline, "get_model",
                            lambda *a, **k: (_Model(), "gemini", ap._call_fn))
        token_usage.reset()

        config = {"agents": ["ai_security"], "block_on": ["critical", "high"]}
        results, _ = _review(target, config, effort="balanced")
        findings = [f for r in results for f in r.findings]
        assert any(f.category == "Stub" for f in findings)

        usage = token_usage.summary()
        assert usage["input_tokens"] == 25
        assert usage["output_tokens"] == 8
        assert usage["total_tokens"] == 33
        print("\nTOKEN_USAGE:", json.dumps(usage))

    def test_large_file_chunks_and_counts_tokens(self, tmp_path, monkeypatch):
        import prism.ai_pipeline as ap_pipeline
        import prism.ai_providers as ap
        import prism.ai_graph as ag
        from prism import token_usage

        monkeypatch.chdir(tmp_path)
        big = tmp_path / "big.py"
        big.write_text("\n".join("x = %d" % i for i in range(1, 1201)))

        payload = {"findings": [], "summary": "ok"}
        calls = {"n": 0}

        class _Response:
            text = json.dumps(payload)
            usage_metadata = type("U", (), {
                "prompt_token_count": 100, "candidates_token_count": 10})()

        class _Model:
            def generate_content(self, *a, **k):
                calls["n"] += 1
                return _Response()

        monkeypatch.setattr(ag, "build_import_graph", lambda *a, **k: {})
        monkeypatch.setattr(ag, "get_cross_file_context", lambda *a, **k: "")
        monkeypatch.setattr(ap_pipeline, "get_model",
                            lambda *a, **k: (_Model(), "gemini", ap._call_fn))
        token_usage.reset()

        findings = ap_pipeline.review_with_agent(
            "S", "big.py", big.read_text(), "ai_security", "", 1200)
        assert calls["n"] >= 2
        assert findings == []
        assert token_usage.summary()["total_tokens"] == calls["n"] * 110

    def test_diff_is_scoped_in_pipeline(self, tmp_path, monkeypatch):
        import prism.ai_pipeline as ap_pipeline
        import prism.ai_providers as ap
        import prism.ai_graph as ag

        monkeypatch.chdir(tmp_path)
        full = "\n".join("line %d" % i for i in range(1, 300))
        diff = ("--- a/app.py\n"
                "+++ b/app.py\n"
                "@@ -1,2 +1,3 @@\n"
                " line1\n"
                "+added = 1\n"
                " line2\n")
        seen = []

        class _Response:
            text = '{"findings": [], "summary": "ok"}'
            usage_metadata = None

        class _Model:
            def generate_content(self, prompt_text, *a, **k):
                seen.append(prompt_text)
                return _Response()

        monkeypatch.setattr(ag, "build_import_graph", lambda *a, **k: {})
        monkeypatch.setattr(ag, "get_cross_file_context", lambda *a, **k: "")
        monkeypatch.setattr(ap_pipeline, "get_model",
                            lambda *a, **k: (_Model(), "gemini", ap._call_fn))
        ap_pipeline.review_with_agent(
            "S", "app.py", full, "ai_security", "", 300, diff)
        # The prompt sent to the model contains the diff, not the 300-line file.
        blob = "\n".join(seen)
        assert "+++ b/app.py" in blob
        assert "line 299" not in blob


def _scan_args(path, effort="lite", json_mode=True):
    return argparse.Namespace(path=path, json=json_mode, effort=effort,
                              fast=False, no_dashboard=True)


class TestScanCommand:
    """prism scan: whole-project audit over full file content."""

    def test_scan_covers_every_file_and_skips_ignored_dirs(self, tmp_path,
                                                           monkeypatch, capsys):
        from prism.cli_commands import _cmd_scan

        monkeypatch.chdir(tmp_path)
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "bad.py").write_text(
            "import subprocess\n\n\ndef run(cmd):\n    subprocess.call(cmd, "
            "shell=True)\n")
        (tmp_path / "pkg" / "ok.py").write_text(
            "def add(a, b):\n    return a + b\n")
        vendored = tmp_path / "node_modules"
        vendored.mkdir()
        (vendored / "x.js").write_text("eval(payload)\n")

        with pytest.raises(SystemExit) as exc:
            _cmd_scan(_scan_args("pkg"))
        assert exc.value.code == 0

        payload = json.loads(capsys.readouterr().out)
        reviewed = {Path(f).name for f in payload["files_reviewed"]}
        assert reviewed == {"bad.py", "ok.py"}
        assert payload["total_findings"] >= 1

    def test_scan_is_advisory_not_a_commit_gate(self, tmp_path, monkeypatch,
                                                capsys):
        from prism.cli_commands import _cmd_scan

        monkeypatch.chdir(tmp_path)
        (tmp_path / "bad.py").write_text(
            "def f(p):\n    eval(p)\n")
        monkeypatch.setattr(sys, "argv", ["prism", "scan"])

        with pytest.raises(SystemExit) as exc:
            _cmd_scan(_scan_args(".", json_mode=False))
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "AUDIT:" in out
        assert "COMMIT BLOCKED" not in out


class TestDoctorCommand:
    """prism doctor: diagnostic, always exits 0."""

    def _run(self):
        from prism.commands_setup import _cmd_doctor
        _cmd_doctor(argparse.Namespace())

    def test_doctor_runs_without_a_configured_key(self, tmp_path, monkeypatch,
                                                  capsys):
        monkeypatch.chdir(tmp_path)
        for var in ("GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                    "OPENROUTER_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY",
                    "DEEPSEEK_API_KEY", "MISTRAL_API_KEY"):
            monkeypatch.delenv(var, raising=False)

        self._run()
        out = capsys.readouterr().out
        assert "PRISM doctor" in out
        assert "GEMINI_API_KEY" in out
        assert "no API key configured" in out
        assert "Result: OK" in out

    def test_doctor_reports_a_broken_effort_value(self, tmp_path, monkeypatch,
                                                  capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "prism.json").write_text(
            json.dumps({"effort": "turbo", "agents": ["policy"]}))

        self._run()
        out = capsys.readouterr().out
        assert "problem(s)" in out
        assert "invalid effort 'turbo'" in out