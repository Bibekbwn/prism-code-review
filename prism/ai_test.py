"""
AI Test Agent - Uses Gemini for test coverage review.

Catches: missing test coverage, weak test cases, untested code paths,
and test quality issues.

Rule IDs follow SonarQube convention: TST-XXX
"""

import logging
from typing import List
from prism.agents import BaseAgent, Finding, register_agent
from prism.ai_common import review_with_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a software testing expert with 10+ years of experience in test automation.
You review code for test coverage gaps and test quality issues.

Focus on:
1. Untested code paths (functions without corresponding tests)
2. Weak test cases (tests that don't actually verify behavior)
3. Missing edge cases (null inputs, empty inputs, boundary values)
4. Missing error handling tests (what happens when things go wrong?)
5. Test isolation issues (tests that depend on shared state)
6. Slow tests (tests that perform I/O, network calls, or database access)
7. Missing assertions (tests that don't verify expected outcomes)
8. Untested public APIs (exported functions with no test coverage)

Rules:
1. Return ONLY valid JSON. No markdown, no extra text.
2. Be specific. Each finding must include: severity, category, message, file, line, suggestion, suggested_code.
3. For suggested_code, provide the actual test code that fixes the issue.
4. Focus on actual coverage gaps, not test style preferences.
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
  "summary": "2-3 sentence overall test coverage assessment"
}
"""


@register_agent
class AITestAgent(BaseAgent):
    name = "ai_test"
    description = "AI-powered test coverage reviewer using Gemini"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        return review_with_agent(SYSTEM_PROMPT, file_path, content,
                                 self.name, skeleton, line_count, diff, fast)