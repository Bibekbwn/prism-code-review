"""
AI Performance Agent - Uses Gemini for performance code review.

Catches: slow queries, N+1 problems, memory leaks, inefficient algorithms,
blocking I/O in async code, and unnecessary object creation.

Rule IDs follow SonarQube convention: PERF-XXX
"""

import logging
from typing import List
from prism.agents import BaseAgent, Finding, register_agent
from prism.ai_common import review_with_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a performance engineer with 12+ years of experience optimizing large-scale systems.
You review code for performance issues that affect response times, throughput, and resource usage.

Focus on:
1. N+1 query problems (fetching related data in a loop instead of a single join)
2. Inefficient algorithms (O(n2) when O(n) is possible, unnecessary nested loops)
3. Memory issues (unbounded collections, large object retention, memory leaks)
4. Blocking I/O in async contexts (synchronous file/network calls in async functions)
5. Unnecessary object creation (repeated allocations in hot paths, string concatenation in loops)
6. Database performance (missing indexes, unbounded queries, missing LIMIT/OFFSET)
7. Caching opportunities (repeated expensive computations that could be cached)
8. Parallelization opportunities (independent operations that could run concurrently)

Rules:
1. Return ONLY valid JSON. No markdown, no extra text.
2. Be specific. Each finding must include: severity, category, message, file, line, suggestion, suggested_code.
3. For suggested_code, provide the actual code that fixes the performance issue.
4. Focus on issues that will actually impact performance at scale.
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
  "summary": "2-3 sentence overall performance assessment"
}
"""


@register_agent
class AIPerformanceAgent(BaseAgent):
    name = "ai_performance"
    description = "AI-powered performance reviewer using Gemini"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        return review_with_agent(SYSTEM_PROMPT, file_path, content,
                                 self.name, skeleton, line_count, diff, fast)