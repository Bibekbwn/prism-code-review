"""
Unit tests for the security secret scanning module.
"""

import pytest
from prism.agents_security import SecurityAgent


class TestScanSecrets:
    """Test the scan_secrets function."""

    def test_no_secrets_found(self):
        diff = """
+++ b/src/main.py
 def hello():
     print("Hello World")
"""
        agent = SecurityAgent()
        result = agent.review("src/main.py", diff, diff)
        assert len(result.findings) == 0

    def test_api_key_detected(self):
        diff = """
+++ b/src/config.py
API_KEY = "sk-1234567890abcdef1234567890abcdef"
"""
        agent = SecurityAgent()
        result = agent.review("src/config.py", diff, diff)
        assert len(result.findings) >= 1
        assert result.findings[0].category == "Secret Exposure"
        assert result.findings[0].severity.value == "critical"

    def test_aws_access_key_detected(self):
        diff = """
+++ b/src/deploy.py
aws_key = "AKIAIOSFODNN7EXAMPLE"
"""
        agent = SecurityAgent()
        result = agent.review("src/deploy.py", diff, diff)
        assert len(result.findings) >= 1
        assert result.findings[0].category == "Secret Exposure"

    def test_password_detected(self):
        diff = """
+++ b/src/db.py
password = "supersecretpassword123"
"""
        agent = SecurityAgent()
        result = agent.review("src/db.py", diff, diff)
        assert len(result.findings) >= 1
        assert result.findings[0].category == "Secret Exposure"

    def test_token_detected(self):
        diff = """
+++ b/src/auth.py
token = "ghp_1234567890abcdef1234567890abcdef"
"""
        agent = SecurityAgent()
        result = agent.review("src/auth.py", diff, diff)
        assert len(result.findings) >= 1
        assert result.findings[0].category == "Secret Exposure"

    def test_file_tracking(self):
        diff = """
+++ b/src/config.py
SECRET_KEY = "my-secret-key-12345"
+++ b/src/utils.py
API_TOKEN = "token-12345-abcde-67890"
"""
        agent = SecurityAgent()
        result = agent.review("src/config.py", diff, diff)
        assert len(result.findings) >= 1