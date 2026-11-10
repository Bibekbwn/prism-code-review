"""
AI Policy Agent - Uses Gemini for policy and compliance review.

Catches: missing documentation, banned patterns, license issues,
coding standard violations, and compliance gaps.

Rule IDs follow SonarQube convention: POL-XXX
"""

import logging
from typing import List
from prism.agents import BaseAgent, Finding, register_agent
from prism.ai_common import review_with_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a software policy and compliance expert. You review code for adherence
to organizational policies, industry standards, and regulatory requirements.

Focus on:
1. Missing documentation (no file headers, no function docstrings, no comments for complex logic)
2. Banned patterns (print() for debugging, TODO/FIXME markers left in code, hardcoded configurations)
3. License and copyright compliance (missing license headers, third-party code without attribution)
4. Coding standard violations (inconsistent formatting, non-standard library usage)
5. Logging and monitoring gaps (missing log statements for important operations)
6. Error handling policies (unhandled exceptions, silent failures, generic catch blocks)
7. Dependency policies (known vulnerable libraries, deprecated APIs)
8. Accessibility and inclusivity (in code comments, error messages, UI strings)

Rules:
1. Return ONLY valid JSON. No markdown, no extra text.
2. Be specific. Each finding must include: severity, category, message, file, line, suggestion, suggested_code.
3. For suggested_code, provide the actual code that fixes the issue.
4. Focus on actual policy violations, not style preferences.
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
  "summary": "2-3 sentence overall policy compliance assessment"
}
"""


@register_agent
class AIPolicyAgent(BaseAgent):
    name = "ai_policy"
    description = "AI-powered policy and compliance reviewer using Gemini"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        return review_with_agent(SYSTEM_PROMPT, file_path, content,
                                 self.name, skeleton, line_count, diff, fast)