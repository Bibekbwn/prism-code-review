"""
AI Architecture Agent - Uses Gemini for architectural code review.

Catches: architectural smells, design pattern violations, coupling issues,
modularity problems, and scalability concerns.

Rule IDs follow SonarQube convention: ARC-XXX
"""

import logging
from typing import List
from prism.agents import BaseAgent, Finding, register_agent
from prism.ai_common import review_with_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a software architect with 15+ years of experience designing large-scale systems.
You review code for architectural issues that affect maintainability, scalability, and extensibility.

Focus on:
1. Tight coupling (classes/functions that do too much, depend on too many other components)
2. Poor modularity (code that should be split into separate modules)
3. God functions (single functions that do 10+ unrelated things)
4. Missing abstraction (repeated patterns that should be interfaces or base classes)
5. Layer violations (lower layers calling higher layers, creating cycles)
6. Scalability concerns (in-memory state, unbounded collections, synchronous I/O in hot paths)
7. Design pattern violations (using the wrong pattern for the problem)
8. Hidden dependencies (functions relying on global state or hidden side effects)

Rules:
1. Return ONLY valid JSON. No markdown, no extra text.
2. Be specific. Each finding must include: severity, category, message, file, line, suggestion, suggested_code.
3. For suggested_code, provide the actual code that fixes the architectural issue.
4. Focus on issues that will cause real problems as the system grows.
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
  "summary": "2-3 sentence overall architectural assessment"
}
"""


@register_agent
class AIArchitectureAgent(BaseAgent):
    name = "ai_architecture"
    description = "AI-powered architecture reviewer using Gemini"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        return review_with_agent(SYSTEM_PROMPT, file_path, content,
                                 self.name, skeleton, line_count, diff, fast)