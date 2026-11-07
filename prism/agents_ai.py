"""
AI Reviewer Agent - Uses Google Gemini for semantic code review.

Checks for logic errors, architectural issues, performance problems,
and security concerns that pattern matching cannot detect.

Rule IDs follow SonarQube convention: AIREV-XXX
"""

import os
import json
import asyncio
import concurrent.futures
import hashlib
import time
import logging
from typing import List, Optional
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent
from prism.context import extract_context

logger = logging.getLogger(__name__)

# Lazy-initialized Gemini model — configured on first use, not at import time
_model = None
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
_available = None


def _get_model():
    """Lazy-load the Gemini model. Returns None if API key is not configured."""
    global _model, _available
    if _model is not None:
        return _model
    if _available is False:
        return None

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        _available = False
        logger.warning("GEMINI_API_KEY not set — AI reviewer disabled")
        return None

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        _model = genai.GenerativeModel("gemini-3.8-flash")
        _available = True
        logger.info("Gemini AI reviewer initialized")
        return _model
    except ImportError:
        _available = False
        logger.warning("google-generativeai not installed — AI reviewer disabled")
        return None
    except Exception as exc:
        _available = False
        logger.error("Failed to initialize Gemini: %s", exc)
        return None


# Maximum file size for AI review (lines). Larger files are skipped to avoid timeouts.
MAX_AI_REVIEW_LINES = 500
# Timeout for each API call in seconds
API_TIMEOUT = 45
# Number of retries on failure
API_MAX_RETRIES = 2
# Circuit breaker: skip AI review after this many consecutive failures
CIRCUIT_BREAKER_THRESHOLD = 3

# Multi-tier cache: in-memory L1 + file-based L2
_cache_l1: dict = {}
_consecutive_failures = 0
_circuit_open = False

SYSTEM_PROMPT = """
You are an expert application security engineer and senior staff engineer.
You review code for logic errors, architectural issues, performance problems,
and security concerns that pattern matching cannot detect.

Rules:
1. Focus on: logic bugs, race conditions, missing error handling, performance issues,
   architectural problems, and subtle security vulnerabilities.
2. Ignore style, formatting, naming conventions, and minor code cleanliness.
3. Return ONLY valid JSON. No markdown, no extra text.
4. Be concise. Each finding must include: severity, category, message, file, line, suggestion.

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
  "summary": "2-3 sentence overall assessment"
}
"""


def _get_cache_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".prism-ai-cache.json")


def _load_file_cache() -> dict:
    try:
        path = _get_cache_path()
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_file_cache(cache: dict):
    try:
        path = _get_cache_path()
        with open(path, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass


_file_cache = _load_file_cache()


def _cache_key(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


async def _review_with_ai(content: str, file_path: str) -> dict:
    """Run AI review with caching."""
    key = _cache_key(content)

    # L1 cache
    if key in _cache_l1:
        return _cache_l1[key]

    # L2 cache
    if key in _file_cache:
        result = _file_cache[key]
        _cache_l1[key] = result
        return result

    # Run AI review
    model = _get_model()
    if model is None:
        return {"findings": [], "summary": "AI review skipped — GEMINI_API_KEY not configured."}

    context = extract_context(content, [])
    prompt = SYSTEM_PROMPT + "\n\nFile: {}\nContext:\n{}\n\nFull content:\n{}".format(
        file_path, context, content[:8000]
    )

    try:
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            _executor, model.generate_content, prompt
        )
        text = response.text or "{}"
    except Exception as exc:
        logger.error("Gemini API call failed: %s", exc)
        return {"findings": [], "summary": "AI review failed — API error."}

    # Clean markdown code blocks
    text = text.replace("```json", "").replace("```", "").strip()

    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        result = {"findings": [], "summary": "Failed to parse Gemini response."}

    # Cache results
    _cache_l1[key] = result
    _file_cache[key] = result
    _save_file_cache(_file_cache)

    return result


@register_agent
class AIReviewerAgent(BaseAgent):
    name = "ai_reviewer"
    description = "Gemini AI semantic code review"

    async def review_async(self, file_path: str, content: str, diff: str) -> dict:
        return await _review_with_ai(content, file_path)

    def review(self, file_path: str, content: str, diff: str):
        """Synchronous review — returns AgentResult. Works for CLI pipeline."""
        findings = self._check(file_path, content, diff)
        from prism.agents import AgentResult
        return AgentResult(
            agent_name=self.name,
            findings=findings,
            passed=len(findings) == 0,
            duration_ms=0.0,
        )

    def _check(self, file_path: str, content: str, diff: str):
        """Run AI review and return list of Findings."""
        global _consecutive_failures, _circuit_open
        
        # Skip AI review for files that are too large — avoids timeouts
        line_count = content.count("\n") + 1
        if line_count > MAX_AI_REVIEW_LINES:
            logger.info("Skipping AI review for %s (%d lines > %d max)",
                        file_path, line_count, MAX_AI_REVIEW_LINES)
            return []

        # Check if API key is available
        model = _get_model()
        if model is None:
            return []

        # Circuit breaker: skip AI review if too many consecutive failures
        if _circuit_open:
            logger.warning("Circuit breaker open — skipping AI review for %s", file_path)
            return []

        try:
            key = _cache_key(content)

            # L1 cache
            if key in _cache_l1:
                result = _cache_l1[key]
                _consecutive_failures = 0  # Reset on cache hit
                _circuit_open = False
            # L2 cache
            elif key in _file_cache:
                result = _file_cache[key]
                _cache_l1[key] = result
                _consecutive_failures = 0  # Reset on cache hit
                _circuit_open = False
            else:
                context = extract_context(content, [])
                prompt = SYSTEM_PROMPT + "\n\nFile: {}\nContext:\n{}\n\nFull content:\n{}".format(
                    file_path, context, content[:8000]
                )
                
                # Retry logic with exponential backoff
                result = None
                for attempt in range(API_MAX_RETRIES + 1):
                    try:
                        response = model.generate_content(
                            prompt, request_options={"timeout": API_TIMEOUT}
                        )
                        text = response.text or "{}"
                        text = text.replace("```json", "").replace("```", "").strip()
                        result = json.loads(text)
                        break  # Success — exit retry loop
                    except json.JSONDecodeError:
                        result = {"findings": [], "summary": "Failed to parse Gemini response."}
                        break  # Parse error — no point retrying
                    except Exception as exc:
                        if attempt < API_MAX_RETRIES:
                            wait = 2 ** attempt  # 1s, 2s
                            logger.warning("AI review attempt %d/%d failed: %s. Retrying in %ds...",
                                           attempt + 1, API_MAX_RETRIES + 1, exc, wait)
                            time.sleep(wait)
                        else:
                            logger.error("AI review failed after %d attempts: %s",
                                         API_MAX_RETRIES + 1, exc)
                
                if result is None:
                    result = {"findings": [], "summary": "AI review failed — API error after {} attempts.".format(API_MAX_RETRIES + 1)}
                    _consecutive_failures += 1
                    if _consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                        _circuit_open = True
                        logger.error("Circuit breaker opened after %d consecutive failures — AI review disabled for this run", _consecutive_failures)
                else:
                    _consecutive_failures = 0  # Reset on success
                    _circuit_open = False

                # Cache results
                _cache_l1[key] = result
                _file_cache[key] = result
                _save_file_cache(_file_cache)
        except Exception as exc:
            logger.error("AI review failed: %s", exc)
            _consecutive_failures += 1
            if _consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                _circuit_open = True
                logger.error("Circuit breaker opened after %d consecutive failures", _consecutive_failures)
            return []

        findings = []
        for item in result.get("findings", []):
            try:
                line_val = item.get("line")
                if line_val is not None:
                    try:
                        line_val = int(line_val)
                    except (ValueError, TypeError):
                        line_val = None

                findings.append(Finding(
                    agent=self.name,
                    severity=Severity(item.get("severity", "low")),
                    category=item.get("category", "AI Review"),
                    message=item.get("message", ""),
                    file=item.get("file", file_path),
                    line=line_val,
                    suggestion=item.get("suggestion"),
                    suggested_code=item.get("suggested_code"),
                    blocker=Blocker.BLOCKS if item.get("severity") in ("critical", "high") else Blocker.WARNS,
                    confidence=0.85,
                    rule_id="AIREV-001",
                ))
            except Exception as exc:
                logger.warning("AI finding parse error: %s", exc)
                continue

        return findings