"""Product-hardening tests: diff mapping, token accounting, provider catalogue,
and packaging metadata.

These lock the behaviours that make PRISM usable as a distributable product
rather than a demo: PR reviews must be diff-scoped, token usage must be
reported, free and paid providers must both work, and the package must be
installable.
"""

import sys
import types


class TestAgentRegistration:
    def test_all_ten_agents_registered(self):
        # Importing the CLI registers the regex and AI agent modules.
        import importlib
        importlib.import_module("prism.cli")
        from prism.agents import AGENT_REGISTRY
        expected = {
            "security", "quality", "policy", "test",
            "ai_security", "ai_quality", "ai_policy", "ai_test",
            "ai_architecture", "ai_performance",
        }
        assert expected <= set(AGENT_REGISTRY)


class TestDiffMapping:
    DIFF = (
        "diff --git a/app.py b/app.py\n"
        "index 111..222 100644\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,4 @@\n"
        " line1\n"
        "+added = 1\n"
        " line2\n"
        " line3\n"
        "@@ -10,2 +11,2 @@\n"
        "-old = 2\n"
        "+new = 3\n"
        " tail"
    )

    def test_line_map(self):
        from prism.ai_pipeline import _build_line_map
        m = _build_line_map(self.DIFF)
        assert m[4] is None          # hunk header
        assert m[5] == 1             # context -> new line 1
        assert m[6] == 2             # added -> new line 2
        assert m[7] == 3             # context -> new line 3
        assert m[8] == 4             # context -> new line 4
        assert m[9] is None          # second hunk header
        assert m[10] is None         # removed line
        assert m[11] == 11           # added -> new line 11
        assert m[12] == 12           # context -> new line 12

    def test_remap_one(self):
        from prism.ai_pipeline import _build_line_map, _remap_one
        from prism.agents import Finding, Severity
        m = _build_line_map(self.DIFF)
        f = Finding(agent="x", severity=Severity.LOW, category="c",
                    message="m", file="app.py", line=7)
        _remap_one(f, m)
        assert f.line == 2

    def test_review_sends_diff_not_full_file(self, monkeypatch):
        import prism.ai_pipeline as ap
        import prism.ai_graph as ag
        sent = []

        def call_fn(model, sp, fp, content, agent, sk, to, ctx):
            sent.append(content)
            return {"findings": [], "summary": "ok"}

        monkeypatch.setattr(ap, "get_model",
                            lambda *a, **k: (object(), "gemini", call_fn))
        monkeypatch.setattr(ag, "build_import_graph", lambda *a, **k: {})
        monkeypatch.setattr(ag, "get_cross_file_context", lambda *a, **k: "")
        full = "\n".join("line %d" % i for i in range(1, 200))
        ap.review_with_agent("S", "app.py", full, "ai_security", "", 200, self.DIFF)
        assert sent == [self.DIFF]

    def test_remapped_line_is_verified_against_full_file(self, monkeypatch):
        import prism.ai_pipeline as ap
        import prism.ai_graph as ag
        full = "\n".join("line %d" % i for i in range(1, 21))
        payload = {"findings": [{
            "severity": "high", "category": "Stub", "message": "stub",
            "file": "app.py", "line": 7, "suggestion": "fix"}], "summary": "ok"}

        monkeypatch.setattr(ap, "get_model",
                            lambda *a, **k: (object(), "gemini",
                                             lambda *a, **k: payload))
        monkeypatch.setattr(ag, "build_import_graph", lambda *a, **k: {})
        monkeypatch.setattr(ag, "get_cross_file_context", lambda *a, **k: "")
        findings = ap.review_with_agent(
            "S", "app.py", full, "ai_security", "", 20, self.DIFF)
        # diff line 6 maps to file line 2; verification must not drop it.
        assert any(f.line == 2 for f in findings)


class TestTokenUsage:
    def setup_method(self):
        from prism import token_usage
        token_usage.reset()

    def test_record_and_summary(self):
        from prism import token_usage
        token_usage.record("gemini", "m1", 10, 5)
        token_usage.record("openai", "m2", 20, 7)
        s = token_usage.summary()
        assert s["calls"] == 2
        assert s["input_tokens"] == 30
        assert s["output_tokens"] == 12
        assert s["total_tokens"] == 42
        assert s["by_provider"]["gemini"]["calls"] == 1

    def test_estimate(self):
        from prism import token_usage
        assert token_usage.estimate_tokens("") == 0
        assert token_usage.estimate_tokens("a" * 40) == 10

    def test_format_summary_empty(self):
        from prism import token_usage
        assert "no AI calls" in token_usage.format_summary()

    def test_estimated_flag(self):
        from prism import token_usage
        token_usage.record("x", "m", 1, 1, estimated=True)
        assert token_usage.summary()["estimated_calls"] == 1

    def test_reset(self):
        from prism import token_usage
        token_usage.record("x", "m", 1, 1)
        token_usage.reset()
        assert token_usage.summary()["calls"] == 0

    def test_provider_call_records_tokens(self, monkeypatch):
        from prism import ai_providers as ap
        from prism import token_usage
        token_usage.reset()

        class _Usage:
            prompt_token_count = 11
            candidates_token_count = 4

        class _Response:
            text = '{"findings": [], "summary": "ok"}'
            usage_metadata = _Usage()

        class _Model:
            def generate_content(self, *a, **k):
                return _Response()

        monkeypatch.setattr(ap, "get_model",
                            lambda *a, **k: (_Model(), "gemini", ap._call_fn))
        result = ap._call_fn(_Model(), "S", "app.py", "x = 1\n", "ai_security")
        assert result["summary"] == "ok"
        s = token_usage.summary()
        assert s["input_tokens"] == 11
        assert s["output_tokens"] == 4
        assert s["estimated_calls"] == 0


class TestProviderCatalogue:
    def test_aliases(self, monkeypatch):
        from prism import ai_providers as ap
        monkeypatch.delenv("MODEL_PROVIDER", raising=False)
        assert ap._resolve_provider("anthropic") == "claude"
        assert ap._resolve_provider("google") == "gemini"
        assert ap._resolve_provider("gpt") == "openai"

    def test_openrouter_default_base_url(self, monkeypatch):
        from prism import ai_providers as ap
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-abcdef1234567890")
        captured = {}

        class _Client:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        mod = types.ModuleType("openai")
        mod.OpenAI = _Client
        monkeypatch.setitem(sys.modules, "openai", mod)
        client, provider, fn = ap.get_model("openrouter")
        assert provider == "openrouter"
        assert captured["base_url"] == "https://openrouter.ai/api/v1"

    def test_openai_base_url_override(self, monkeypatch):
        from prism import ai_providers as ap
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.local/v1")
        captured = {}

        class _Client:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        mod = types.ModuleType("openai")
        mod.OpenAI = _Client
        monkeypatch.setitem(sys.modules, "openai", mod)
        ap.get_model("openai")
        assert captured["base_url"] == "https://proxy.local/v1"

    def test_unknown_provider(self, monkeypatch):
        from prism import ai_providers as ap
        assert ap.get_model("nope") == (None, None, None)

    def test_catalogue_has_free_and_paid(self):
        from prism import ai_providers as ap
        assert "gemini" in ap.PROVIDERS
        assert "openrouter" in ap.PROVIDERS
        assert "groq" in ap.PROVIDERS
        assert ap.PROVIDERS["groq"]["kind"] == "openai"

    def test_key_set_accepts_new_provider(self, tmp_path, monkeypatch, capsys):
        import prism.commands_setup as cs
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("")
        cs._cmd_key(argparse_namespace(
            action="set", provider="groq", key="gsk-real-key-1234567890"))
        env = (tmp_path / ".env").read_text()
        assert 'GROQ_API_KEY="gsk-real-key-1234567890"' in env
        assert "MODEL_PROVIDER=groq" in env


def argparse_namespace(**kwargs):
    import argparse
    return argparse.Namespace(**kwargs)


class TestPackaging:
    def test_pyproject_metadata(self):
        import tomllib
        from pathlib import Path
        root = Path(__file__).parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
        assert project["name"]
        assert project["version"]
        assert project["scripts"]["prism"] == "prism.cli:main"
        extras = project["optional-dependencies"]
        for name in ("gemini", "claude", "openai", "dev"):
            assert name in extras
        assert data["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]

    def test_entry_point_callable(self):
        from prism.cli import main
        assert callable(main)

    def test_env_example_documents_free_providers(self):
        from pathlib import Path
        root = Path(__file__).parent.parent
        text = (root / ".env.example").read_text(encoding="utf-8")
        for token in ("OPENROUTER_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY"):
            assert token in text

class TestSecurityPatterns:
    def test_subprocess_shell_true_detected(self):
        from prism.agents_security import SecurityAgent
        code = "import subprocess\nsubprocess.call(cmd, shell=True)\n"
        findings = SecurityAgent()._check("app.py", code, "")
        assert any(f.rule_id == "SECU-203" for f in findings)

    def test_subprocess_shell_false_not_flagged(self):
        from prism.agents_security import SecurityAgent
        code = "import subprocess\nsubprocess.run(cmd, shell=False)\n"
        findings = SecurityAgent()._check("app.py", code, "")
        assert not any(f.rule_id == "SECU-203" for f in findings)
