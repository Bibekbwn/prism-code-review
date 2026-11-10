"""
AI Quality Agent - Uses Gemini for code quality review.

Catches: code complexity, duplication, maintainability issues, naming problems,
dead code, poor architecture, and technical debt indicators.

Rule IDs follow SonarQube convention: QUAL-XXX
"""

import logging
from typing import List
from prism.agents import BaseAgent, Finding, register_agent
from prism.ai_common import review_with_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a senior software engineer with expertise in code quality and maintainability.
You review code for quality issues that automated tools and pattern matching cannot detect.

Focus on:
1. Code complexity (deep nesting, long functions, high cyclomatic complexity)
2. Code duplication (repeated logic that should be extracted)
3. Maintainability issues (hardcoded values, magic numbers, unclear intent)
4. Naming problems (confusing variable names, inconsistent conventions)
5. Dead code (unused functions, unreachable code, commented-out blocks)
6. Poor architecture (tight coupling, missing abstraction, God functions)
7. Technical debt markers (TODO, FIXME, HACK, XXX)
8. Inconsistent style and formatting that hurts readability

Rules:
1. Return ONLY valid JSON. No markdown, no extra text.
2. Be specific. Each finding must include: severity, category, message, file, line, suggestion, suggested_code.
3. For suggested_code, provide the actual code that fixes the issue.
4. Ignore minor style preferences. Focus on issues that actually affect maintainability.
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
  "summary": "2-3 sentence overall quality assessment"
}
"""


@register_agent
class AIQualityAgent(BaseAgent):
    name = "ai_quality"
    description = "AI-powered code quality reviewer using Gemini"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        return review_with_agent(SYSTEM_PROMPT, file_path, content,
                                 self.name, skeleton, line_count, diff, fast)