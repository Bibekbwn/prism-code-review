"""Provider request-shaping tests.

Claude and OpenAI cannot be exercised live without paid keys, but the payload
they send and the JSON they must return are pure functions of the SDK call.
These tests pin both, so a provider refactor cannot silently break the wire
format.
"""

import prism.ai_providers as ap
import pytest


@pytest.fixture(autouse=True)
def _reset_circuit():
    ap._circuit_failures = 0
    ap._circuit_open_until = 0.0
    yield
    ap._circuit_failures = 0
    ap._circuit_open_until = 0.0


class TestGeminiPayload:
    def test_requests_json_mode_and_passes_timeout(self):
        captured = {}

        class _Response:
            text = '{"findings": []}'

        class _Model:
            def generate_content(self, prompt, generation_config=None,
                                 request_options=None):
                captured["prompt"] = prompt
                captured["generation_config"] = generation_config
                captured["request_options"] = request_options
                return _Response()

        result = ap._call_fn(_Model(), "SYSTEM", "a.py", "x = 1",
                             "ai_security", "SKEL", 7)
        assert result == {"findings": []}
        assert captured["generation_config"]["response_mime_type"] == \
            "application/json"
        assert captured["request_options"]["timeout"] == 7
        assert "SYSTEM" in captured["prompt"]


class TestClaudePayload:
    def test_payload_and_parsing(self):
        captured = {}

        class _Messages:
            @staticmethod
            def create(**kwargs):
                captured.update(kwargs)

                class _Block:
                    text = ('{"findings": [{"severity": "high", '
                            '"message": "eval", "line": 2}]}')

                class _Response:
                    content = [_Block()]

                return _Response()

        class _Model:
            messages = _Messages()

        result = ap._call_claude(_Model(), "SYSTEM", "a.py", "x = 1",
                                 "ai_security", "SKEL", 5)
        assert captured["system"] == "SYSTEM"
        assert captured["messages"][0]["role"] == "user"
        assert result["findings"][0]["severity"] == "high"


class TestOpenAIPayload:
    def test_payload_and_parsing(self):
        captured = {}

        class _Completions:
            @staticmethod
            def create(**kwargs):
                captured.update(kwargs)

                class _Message:
                    content = '{"findings": []}'

                class _Choice:
                    message = _Message()

                class _Response:
                    choices = [_Choice()]

                return _Response()

        class _Chat:
            completions = _Completions()

        class _Model:
            chat = _Chat()

        result = ap._call_openai(_Model(), "SYSTEM", "a.py", "x = 1",
                                 "ai_quality", "SKEL", 5)
        assert captured["response_format"] == {"type": "json_object"}
        assert captured["messages"][0]["role"] == "system"
        assert result == {"findings": []}


class TestProviderSelection:
    def test_unknown_provider_returns_none(self):
        model, provider, call = ap.get_model(provider="does-not-exist")
        assert (model, provider, call) == (None, None, None)

    def test_placeholder_key_is_rejected(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "your-api-key-here")
        model, provider, call = ap.get_model(provider="gemini")
        assert (model, provider, call) == (None, None, None)


class TestModelFailureReason:
    """A missing SDK and a missing key both return None; the reason must not.

    `pip install <wheel>` installs no SDK, so every developer who follows the
    hand-over guide hits the no-SDK path with a key already set. Reporting that
    as "no API key" sends them to re-enter a key that is already correct.
    """

    def test_missing_key_is_reported_as_no_key(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        ap.get_model(provider="gemini")
        reason, name, detail = ap.last_model_failure()
        assert reason == "no_key"
        assert name == "gemini"
        assert detail == "GEMINI_API_KEY"

    def test_placeholder_key_is_reported_as_no_key(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "your-api-key-here")
        ap.get_model(provider="gemini")
        assert ap.last_model_failure()[0] == "no_key"

    def test_unknown_provider_is_reported_as_such(self, monkeypatch):
        ap.get_model(provider="does-not-exist")
        reason, name, _detail = ap.last_model_failure()
        assert reason == "unknown_provider"
        assert name == "does-not-exist"

    def test_missing_sdk_is_reported_as_no_sdk(self, monkeypatch):
        # A real key, but the SDK is not importable: the failure is the SDK.
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyREALKEY1234567890")
        monkeypatch.setitem(__import__("sys").modules, "google.generativeai",
                            None)
        ap.get_model(provider="gemini")
        reason, name, _detail = ap.last_model_failure()
        assert reason == "no_sdk"
        assert name == "gemini"

    def test_failure_carries_the_provider_even_though_none_is_returned(self,
                                                                      monkeypatch):
        # get_model() returns (None, None, None) on failure, so the provider
        # name the caller needs for its message is only available here.
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyREALKEY1234567890")
        monkeypatch.setitem(__import__("sys").modules, "google.generativeai",
                            None)
        model, provider, call = ap.get_model(provider="gemini")
        assert (model, provider, call) == (None, None, None)
        assert ap.last_model_failure()[1] == "gemini"

    def test_a_later_failure_replaces_the_earlier_one(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        ap.get_model(provider="gemini")
        assert ap.last_model_failure()[0] == "no_key"
        # A provider whose SDK is absent still resolves past the key check; the
        # failure recorded is the SDK, never a stale key failure.
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyREALKEY1234567890")
        monkeypatch.setitem(__import__("sys").modules, "google.generativeai",
                            None)
        ap.get_model(provider="gemini")
        assert ap.last_model_failure()[0] == "no_sdk"


class TestSdkInstallHint:
    """The hint must name the extra that actually supplies the SDK."""

    def test_gemini_maps_to_the_gemini_extra(self):
        assert ap.sdk_install_hint("gemini") == "pip install 'prism-review[gemini]'"

    def test_claude_maps_to_the_claude_extra(self):
        assert ap.sdk_install_hint("claude") == "pip install 'prism-review[claude]'"

    def test_openai_compatible_providers_share_the_openai_extra(self):
        for name in ("openai", "openrouter", "groq", "together",
                     "deepseek", "mistral"):
            assert ap.sdk_extra(name) == "openai"

    def test_alias_resolves_before_lookup(self):
        assert ap.sdk_extra("google") == "gemini"

    def test_unknown_provider_has_no_hint(self):
        assert ap.sdk_install_hint("does-not-exist") is None

    def test_every_declared_provider_has_an_extra(self):
        for name, spec in ap.PROVIDERS.items():
            assert ap.sdk_extra(name) == spec["kind"]


class TestIntEnv:
    """Tuning variables are read at import time; a typo must not break the CLI."""

    def test_parses_an_integer(self, monkeypatch):
        monkeypatch.setenv("PRISM_TEST_INT", "42")
        assert ap._int_env("PRISM_TEST_INT", 7) == 42

    def test_falls_back_when_unset(self, monkeypatch):
        monkeypatch.delenv("PRISM_TEST_INT", raising=False)
        assert ap._int_env("PRISM_TEST_INT", 7) == 7

    def test_falls_back_on_a_non_number(self, monkeypatch):
        monkeypatch.setenv("PRISM_TEST_INT", "not-a-number")
        assert ap._int_env("PRISM_TEST_INT", 7) == 7

    def test_max_content_chars_is_configurable(self, monkeypatch):
        # .env.example documents PRISM_MAX_CONTENT_CHARS; it must actually be read.
        monkeypatch.setenv("PRISM_MAX_CONTENT_CHARS", "1234")
        assert ap._int_env("PRISM_MAX_CONTENT_CHARS", 16000) == 1234
