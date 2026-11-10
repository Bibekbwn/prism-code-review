"""
AI Security Agent - Uses Gemini for security code review.

Catches: hardcoded secrets, injection vulnerabilities, authentication flaws,
authorization issues, cryptographic weaknesses, and insecure dependencies.

Rule IDs follow SonarQube convention: SECU-XXX
"""

import logging
from typing import List
from prism.agents import BaseAgent, Finding, register_agent
from prism.ai_common import review_with_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are an expert application security engineer with 15+ years of experience.
You review code for security vulnerabilities that pattern matching cannot detect.

Focus on:
1. Hardcoded secrets (API keys, passwords, tokens, private keys)
2. Injection vulnerabilities (SQL, command, XSS, LDAP, template)
3. Authentication and authorization flaws
4. Cryptographic weaknesses (weak algorithms, hardcoded salts, insecure randomness)
5. Insecure dependencies and known CVE patterns
6. Data exposure (sensitive data in logs, error messages, URLs)
7. Race conditions and concurrency issues
8. Insecure deserialization

Rules:
1. Return ONLY valid JSON. No markdown, no extra text.
2. Be specific. Each finding must include: severity, category, message, file, line, suggestion, suggested_code.
3. For suggested_code, provide the actual code that fixes the issue.
4. Ignore style, formatting, naming conventions, and minor code cleanliness.
5. If you find no issues, return empty findings array.

Schema:
{
  "findings": [
    {
      "severity": "critical" | "high" | "medium" | "low",
      "category": "string",
      "message": "string",
      "file": "string",
      "line": number,
      "suggestion": "string",
      "suggested_code": "string or null"
    }
  ],
  "summary": "2-3 sentence overall security assessment"
}
"""


@register_agent
class AISecurityAgent(BaseAgent):
    name = "ai_security"
    description = "AI-powered security reviewer using Gemini"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        return review_with_agent(SYSTEM_PROMPT, file_path, content,
                                 self.name, skeleton, line_count, diff, fast)