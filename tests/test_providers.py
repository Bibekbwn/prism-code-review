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