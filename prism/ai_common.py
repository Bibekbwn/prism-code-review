"""
Shared AI agent utility with retry logic, timeout handling, and circuit breaker.

Key features:
1. Retry with exponential backoff (1s, 2s, 4s)
2. Circuit breaker: skip after 3 consecutive failures
3. Agent isolation: one agent failing does not affect others
4. Configurable timeout per agent
5. Content size limiting to avoid API timeouts
6. AST-based structural skeleton for senior-dev context
"""

import os
import re
import json
import time
import logging
import ast
import importlib
import concurrent.futures
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

API_TIMEOUT = 120
MAX_RETRIES = 3
CIRCUIT_BREAKER_THRESHOLD = 3
MAX_CONTENT_CHARS = 16000
CHUNK_OVERLAP = 20

# File-size tiers: (threshold_lines, timeout_multiplier, whole_file_agents)
# Agents in whole_file_agents run via two-pass (summarize chunks, then review
# skeleton + summaries). Agents NOT in the list run on every chunk directly.
TIERS = [
    (400, 1.0, []),                          # small: all agents, single call
    (2000, 1.5, ["ai_test", "ai_policy"]),   # medium: test+policy use two-pass
    (10000, 2.0, ["ai_test", "ai_policy", "ai_security", "ai_performance"]),  # large: 4 agents two-pass
    (999999, 3.0, ["ai_test", "ai_policy", "ai_security", "ai_performance", "ai_quality"]),  # 10k+: quality two-pass
]

# Categories that have a deterministic regex equivalent. AI findings in these
# categories get cross-checked against the regex agents (the CodeRabbit
# "verification agent" pattern). Semantic categories are left untouched.
_CROSS_CHECK_CATEGORIES = {
    "Secret Exposure",
    "Dangerous Pattern",
    "Duplication",
    "File Length",
    "Todo",
    "Naming Convention",
}


def get_tier_for_file(line_count: int) -> tuple:
    """Return (timeout_multiplier, whole_file_agents) for a file of given line count."""
    for threshold, multiplier, whole_file in TIERS:
        if line_count <= threshold:
            return multiplier, whole_file
    return TIERS[-1][1], TIERS[-1][2]


def chunk_content(content: str, max_lines: int = 400,
                  overlap: int = 20) -> list:
    """Split content into overlapping chunks for large files.

    Each chunk is max_lines long with overlap lines of context between chunks.
    Returns list of (start_line, chunk_text) tuples.
    """
    lines = content.split("\n")
    if len(lines) <= max_lines:
        return [(1, content)]

    chunks = []
    start = 0
    while start < len(lines):
        end = min(start + max_lines, len(lines))
        chunk = "\n".join(lines[start:end])
        chunks.append((start + 1, chunk))  # 1-indexed line number
        if end >= len(lines):
            break
        start = end - overlap  # overlap for boundary context

    return chunks


def build_skeleton(file_path: str, content: str) -> str:
    """Extract a compact structural summary from Python source.

    Returns a skeleton showing imports, classes, functions, and line numbers.
    This gives the AI a table-of-contents so it can reason about architecture
    even when the full file is too large to fit in one prompt.
    Non-Python files return an empty string.
    """
    if not file_path.endswith('.py'):
        return ""

    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return ""

    skeleton = ["File: {}".format(file_path)]

    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")

    if imports:
        skeleton.append("Imports: {}".format(", ".join(imports)))

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            skeleton.append(
                "Class {} (line {})".format(node.name, node.lineno)
            )
            for m in methods:
                skeleton.append("  - {}".format(m))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            skeleton.append(
                "Function {} (line {})".format(node.name, node.lineno)
            )

    return "\n".join(skeleton)


def get_model(provider: str = None, model_name: str = None):
    """Lazy-load an LLM model. Supports gemini, claude, and openai.

    Provider is selected via MODEL_PROVIDER env var (default: gemini).
    Returns (model, provider_name, call_fn) or (None, None, None) if no key is set.
    """
    provider = (provider or os.getenv("MODEL_PROVIDER", "gemini")).lower()

    if provider == "gemini":
        model_name = model_name or os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning("GEMINI_API_KEY not set")
            return None, None, None
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            return genai.GenerativeModel(model_name), "gemini", _call_fn
        except Exception as exc:
            logger.error("Failed to initialize Gemini: %s", exc)
            return None, None, None

    elif provider == "claude":
        model_name = model_name or os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-20241022")
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set")
            return None, None, None
        try:
            anthropic = __import__("anthropic")
            client = anthropic.Anthropic(api_key=api_key)
            return client, "claude", _call_claude
        except Exception as exc:
            logger.error("Failed to initialize Claude: %s", exc)
            return None, None, None

    elif provider == "openai":
        model_name = model_name or os.getenv("OPENAI_MODEL", "gpt-4o")
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set")
            return None, None, None
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            return client, "openai", _call_openai
        except Exception as exc:
            logger.error("Failed to initialize OpenAI: %s", exc)
            return None, None, None

    logger.error("Unknown MODEL_PROVIDER: %s", provider)
    return None, None, None


def _call_fn(model, system_prompt, file_path, content, agent_name,
                 skeleton="", timeout=None, cross_file_context=""):
    """Call Gemini API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    content_to_send = content[:MAX_CONTENT_CHARS]
    prompt_parts = [system_prompt]
    if cross_file_context:
        prompt_parts.append(cross_file_context)
    if skeleton:
        prompt_parts.append(
            "\n## Structural Skeleton (table of contents for this file)\n"
            + skeleton
        )
    prompt_parts.append("\n## File: {}\n".format(file_path))
    prompt_parts.append("\n## Content\n{}".format(content_to_send))
    prompt = "\n".join(prompt_parts)

    # Wrap generate_content so the shared retry logic gets a plain string.
    # Gemini returns a GenerateContentResponse — extract .text before the
    # JSON-cleaning step in _call_with_retry runs.
    def _do_generate(prompt_text, _timeout=timeout):
        response = model.generate_content(
            prompt_text, request_options={"timeout": _timeout}
        )
        return response.text or "{}"

    return _call_with_retry(_do_generate, prompt, agent_name, timeout)


def _call_claude(model, system_prompt, file_path, content, agent_name,
                 skeleton="", timeout=None, cross_file_context=""):
    """Call Claude API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    content_to_send = content[:MAX_CONTENT_CHARS]
    prompt_parts = []
    if cross_file_context:
        prompt_parts.append(cross_file_context)
    if skeleton:
        prompt_parts.append(
            "\n## Structural Skeleton (table of contents for this file)\n"
            + skeleton
        )
    prompt_parts.append("\n## File: {}\n".format(file_path))
    prompt_parts.append("\n## Content\n{}".format(content_to_send))
    user_prompt = "\n".join(prompt_parts)

    def _do_call():
        response = model.messages.create(
            model=os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-20241022"),
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text

    return _call_with_retry(_do_call, None, agent_name, timeout)


def _call_openai(model, system_prompt, file_path, content, agent_name,
                 skeleton="", timeout=None, cross_file_context=""):
    """Call OpenAI API with retry logic and circuit breaker."""
    if timeout is None:
        timeout = API_TIMEOUT
    content_to_send = content[:MAX_CONTENT_CHARS]
    prompt_parts = []
    if cross_file_context:
        prompt_parts.append(cross_file_context)
    if skeleton:
        prompt_parts.append(
            "\n## Structural Skeleton (table of contents for this file)\n"
            + skeleton
        )
    prompt_parts.append("\n## File: {}\n".format(file_path))
    prompt_parts.append("\n## Content\n{}".format(content_to_send))
    user_prompt = "\n".join(prompt_parts)

    def _do_call():
        response = model.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    return _call_with_retry(_do_call, None, agent_name, timeout)


def _call_with_retry(call_fn, prompt, agent_name, timeout):
    """Shared retry + JSON parse logic for all providers."""
    last_error = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            if prompt is not None:
                text = call_fn(prompt)
            else:
                text = call_fn()
            text = (text or "{}").replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except json.JSONDecodeError:
            return {"findings": [], "summary": "Parse error"}
        except Exception as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                wait = 2 ** attempt
                logger.warning(
                    "%s attempt %d/%d failed: %s. Retrying in %ds...",
                    agent_name, attempt + 1, MAX_RETRIES + 1, exc, wait
                )
                time.sleep(wait)
            else:
                logger.error(
                    "%s failed after %d attempts: %s",
                    agent_name, MAX_RETRIES + 1, exc
                )
    return {"findings": [], "summary": "API error after {} attempts".format(MAX_RETRIES + 1)}


def call_fn(model, system_prompt: str, file_path: str,
                content: str, agent_name: str = "unknown",
                skeleton: str = "", timeout: int = None,
                cross_file_context: str = "") -> Dict[str, Any]:
    """Public entry point for AI code review.

    Thin wrapper over _call_fn — kept for backwards compatibility with
    call sites that pass the legacy positional signature. All prompt
    building and retry logic lives in _call_fn so there is a single
    implementation.
    """
    return _call_fn(model, system_prompt, file_path, content, agent_name,
                    skeleton=skeleton, timeout=timeout,
                    cross_file_context=cross_file_context)


def parse_findings(result: Dict, file_path: str, agent_name: str) -> list:
    """Parse Gemini JSON response into Finding objects.

    Generates a unique rule_id per finding (e.g. SECU-AI-001, SECU-AI-002)
    so deduplication and suppression work correctly.
    """
    from prism.agents import Finding, Severity, Blocker

    # Map agent name to rule prefix (SECU, QUAL, POL, TST, ARC, PERF)
    agent_prefix_map = {
        "ai_security": "SECU",
        "ai_quality": "QUAL",
        "ai_policy": "POL",
        "ai_test": "TST",
        "ai_architecture": "ARC",
        "ai_performance": "PERF",
    }
    agent_prefix = agent_prefix_map.get(agent_name, agent_name.upper()[:4])

    findings = []
    rule_counter = 0
    for item in result.get("findings", []):
        try:
            line_val = item.get("line")
            if line_val is not None:
                try:
                    line_val = int(line_val)
                except (ValueError, TypeError):
                    line_val = None

            sev_str = item.get("severity", "low").lower()

            # Unique rule ID per finding: SECU-AI-001, SECU-AI-002, etc.
            rule_counter += 1
            rule_id = "{}-AI-{:03d}".format(agent_prefix, rule_counter)

            # Accept confidence from LLM response, default to 0.85
            confidence = item.get("confidence", 0.85)
            try:
                confidence = float(confidence)
            except (ValueError, TypeError):
                confidence = 0.85

            findings.append(Finding(
                agent=agent_name,
                severity=Severity(sev_str),
                category=item.get("category", agent_name),
                message=item.get("message", ""),
                file=item.get("file", file_path),
                line=line_val,
                suggestion=item.get("suggestion"),
                suggested_code=item.get("suggested_code"),
                blocker=Blocker.BLOCKS if sev_str in ("critical", "high") else Blocker.WARNS,
                confidence=confidence,
                rule_id=rule_id,
            ))
        except Exception as exc:
            logger.warning("Finding parse error: %s", exc)
            continue

    return findings


def verify_findings(findings, file_path, content):
    """Validate AI-generated findings before they reach the user.

    LLMs hallucinate. This catches the most common errors:
    1. Line number outside file bounds
    2. Finding pointing to a non-existent file
    3. suggested_code that is not valid syntax
    4. Duplicate findings (same agent, line, and message)
    5. Finding whose message references code that doesn't exist at that line
    6. Finding with no deterministic support — the CodeRabbit "verification
       agent" pattern. If a regex agent would also flag the claimed pattern,
       the finding is confirmed. If not, confidence is halved (not dropped)
       so the finding still surfaces but is clearly unverified.

    Categories in _CROSS_CHECK_CATEGORIES get the deterministic cross-check.
    Semantic categories (architectural smells, missing documentation) are
    left untouched — no regex can confirm them.

    Returns only findings that pass all checks.
    """
    from prism.agents import Finding, Severity, Blocker

    if not findings:
        return []

    lines = content.split("\n")
    max_line = len(lines)
    verified = []
    seen = set()

    for f in findings:
        # 1. Line bounds check
        if f.line is not None:
            if f.line < 1 or f.line > max_line:
                logger.warning(
                    "Dropped finding: line %s out of bounds (file has %d lines)",
                    f.line, max_line
                )
                continue

        # 2. File existence check — only drop if path is clearly invalid
        # (empty, None, or contains null bytes). Don't check disk existence
        # because the file may be staged-but-not-yet-written.
        if not file_path or '\x00' in file_path:
            logger.warning("Dropped finding: invalid file path '%s'", file_path)
            continue

        # 3. Duplicate detection (same agent, line, and message)
        dedup_key = (f.agent, f.line, f.message.strip().lower()[:100])
        if dedup_key in seen:
            logger.warning("Dropped duplicate finding: %s", f.message[:80])
            continue
        seen.add(dedup_key)

        # 4. suggested_code syntax check
        if f.suggested_code:
            try:
                ast.parse(f.suggested_code)
            except SyntaxError:
                logger.warning(
                    "Dropped finding: suggested_code is invalid syntax: %s",
                    f.suggested_code[:80]
                )
                continue

        # 5. Message relevance check — the finding's message should reference
        #    something that actually exists at or near the claimed line.
        #    Only check words that look like code identifiers (snake_case or
        #    camelCase), not common English words like "issue" or "problem".
        if f.line is not None and f.line <= max_line:
            nearby = "\n".join(lines[max(0, f.line - 3):f.line + 3])
            words = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', f.message))
            # Only check words that look like code identifiers
            code_words = {
                w for w in words
                if '_' in w or re.match(r'^[a-z]+[A-Z]', w)
            }
            if code_words:
                found_any = any(
                    w.lower() in nearby.lower() for w in code_words
                )
                if not found_any:
                    logger.warning(
                        "Dropped finding: message references code not found at line %s",
                        f.line
                    )
                    continue

        # 6. Deterministic cross-check — the CodeRabbit verification pattern.
        #    Only applies to categories that have a deterministic regex
        #    equivalent. Semantic findings (architectural smells, missing
        #    documentation) are left untouched — no regex can confirm them.
        if f.category in _CROSS_CHECK_CATEGORIES:
            confirmed, reason = _cross_check(f, lines)
            if not confirmed:
                f.confidence = max(0.1, f.confidence * 0.5)
                logger.info(
                    "Verification: finding at line %s has no deterministic support (%s) — confidence reduced to %.2f",
                    f.line, reason, f.confidence
                )

        verified.append(f)

    logger.info(
        "Verification: %d/%d findings passed checks",
        len(verified), len(findings)
    )
    return verified


def _cross_check(finding, lines):
    """Cross-check an AI finding against deterministic regex patterns.

    Returns (confirmed: bool, reason: str).
    A finding is "confirmed" if a regex pattern from the security or quality
    agents would also flag the claimed line. This is the CodeRabbit
    "verification agent" pattern — the LLM claims something, the regex
    proves it exists.

    We only cross-check findings whose category maps to a known regex rule.
    Findings in unmapped categories (e.g. architectural smells) are returned
    as unconfirmed — they're semantic, not pattern-based.
    """
    line_no = finding.line
    if line_no is None or line_no < 1 or line_no > len(lines):
        return False, "no line to check"

    line_text = lines[line_no - 1]

    # Security: check against SECRET_PATTERNS and DANGEROUS_PATTERNS
    if finding.category in ("Secret Exposure", "Dangerous Pattern"):
        try:
            from prism.agents_security import SECRET_PATTERNS, DANGEROUS_PATTERNS
        except Exception:
            return False, "security patterns unavailable"
        for pattern, _label, _rule_id in SECRET_PATTERNS + DANGEROUS_PATTERNS:
            if re.search(pattern, line_text, re.IGNORECASE):
                return True, "regex pattern matches at claimed line"

    # Quality: check for duplication, long lines, TODO markers
    if finding.category in ("Duplication", "File Length", "Todo"):
        if finding.category == "File Length" and len(line_text) > 120:
            return True, "line exceeds 120 chars"
        if finding.category == "Todo" and re.search(r'TODO|FIXME|XXX', line_text):
            return True, "TODO marker found"

    # Naming convention — check for camelCase in Python files
    if finding.category == "Naming Convention":
        if finding.file and finding.file.endswith(".py"):
            if re.search(r'\b[a-z]+[A-Z]\w*\s*=', line_text):
                return True, "camelCase variable found"

    return False, "no deterministic pattern supports this finding"


def review_with_agent(system_prompt: str, file_path: str,
                      content: str, agent_name: str,
                      skeleton: str = "", line_count: int = None,
                      diff: str = "", fast: bool = False) -> list:
    """Full pipeline: get model, call LLM, parse findings.

    Uses `diff` (git diff hunks) when available — for pre-commit hooks this
    focuses review on changed lines. Falls back to full `content` when no
    diff is provided (e.g. `prism check <file>` on a non-git file).

    When `fast=True`, whole-file agents use two-pass summarization instead
    of running on every chunk. Default is False (full review, more thorough).

    Automatically adapts to file size:
      - Small files (< 400 lines): single call, base timeout
      - Medium files (400-2000 lines): chunked, 1.5x timeout
      - Large files (2000-10000 lines): chunked, 2x timeout
      - 10000+ lines: chunked, 3x timeout

    Two-pass strategy for large files (only when fast=True):
      - Fragment agents (architecture, quality) run on every chunk
      - Whole-file agents (security, test, policy, performance) run once on
        skeleton + chunk summaries (compressed view of the whole file)

    Developers can override timeout via the PRISM_TIMEOUT env var.
    Set line_count to skip auto-detection.
    """
    model, provider, call_fn = get_model()
    if model is None:
        logger.info("%s skipped: no API key for provider", agent_name)
        return []

    if line_count is None:
        line_count = content.count("\n") + 1

    # Use diff (changed lines) when available; fall back to full content
    review_content = diff if diff and diff.strip() else content
    if diff and diff.strip():
        line_count = review_content.count("\n") + 1

    # Build cross-file context (import graph) if available
    repo_path = os.getenv("PRISM_REPO_PATH", os.getcwd())
    graph = build_import_graph(repo_path)
    cross_file_context = get_cross_file_context(file_path, graph, repo_path)

    # Determine tier: timeout multiplier + which agents need whole-file context
    tier_multiplier, whole_file_agents = get_tier_for_file(line_count)
    needs_whole_file = agent_name in whole_file_agents

    # Timeout: env var override > tier-adjusted default
    timeout = int(API_TIMEOUT * tier_multiplier)
    env_timeout = os.getenv("PRISM_TIMEOUT")
    if env_timeout:
        try:
            timeout = int(env_timeout)
        except ValueError:
            pass

    try:
        chunks = chunk_content(content)
        if len(chunks) == 1:
            # Small file — single call
            result = call_fn(model, system_prompt, file_path,
                                 content, agent_name, skeleton, timeout,
                                 cross_file_context)
            raw = parse_findings(result, file_path, agent_name)
            return verify_findings(raw, file_path, content)

        if needs_whole_file and fast:
            # Two-pass: summarize each chunk, then run agent on skeleton + summaries
            logger.info(
                "%s: whole-file agent, summarizing %d chunks first "
                "(%d-line file, timeout=%ds)",
                agent_name, len(chunks), line_count, timeout
            )

            # Pass 1: summarize each chunk in parallel
            summaries = _summarize_chunks(
                model, chunks, file_path, skeleton, timeout, call_fn, provider
            )

            # Pass 2: run agent on skeleton + compressed summaries
            prompt_content = "## Chunk Summaries\n{}".format(summaries)
            result = call_fn(
                model, system_prompt, file_path,
                prompt_content, agent_name, skeleton, timeout,
                cross_file_context,
            )
            raw = parse_findings(result, file_path, agent_name)
            return verify_findings(raw, file_path, content)

        # Default: run on every chunk (full review, more thorough)
        logger.info(
            "%s: %d-line file split into %d chunks (timeout=%ds)",
            agent_name, line_count, len(chunks), timeout
        )
        all_findings = []
        for chunk_start, chunk_text in chunks:
            chunk_skeleton = skeleton if skeleton else ""
            result = call_fn(
                model, system_prompt, file_path,
                chunk_text, agent_name, chunk_skeleton, timeout,
                cross_file_context,
            )
            findings = parse_findings(result, file_path, agent_name)
            # Adjust line numbers from chunk-relative to file-absolute
            for f in findings:
                if f.line:
                    f.line = f.line + chunk_start - 1
            all_findings.extend(findings)

        # Deduplicate by (file, line, rule_id)
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.file, f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return verify_findings(deduped, file_path, content)

    except Exception as exc:
        logger.error("%s pipeline failed: %s", agent_name, exc)
        return []


def _summarize_chunks(model, chunks, file_path, skeleton, timeout, call_fn=None, provider="gemini"):
    """Summarize each chunk in parallel using a lightweight prompt.

    Returns a compressed string of 1-2 line summaries per chunk.
    """
    summary_prompt = (
        "Summarize this code chunk in 1-2 sentences. "
        "Focus on: what functions/classes exist, what they do, "
        "and any notable patterns (security, performance, policy). "
        "Return ONLY the summary, no JSON, no markdown.\n\n"
    )
    if skeleton:
        summary_prompt += "File structure:\n{}\n\n".format(skeleton)

    summaries = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for i, (start, text) in enumerate(chunks):
            prompt = summary_prompt + "Chunk {} (lines {}-{})\n{}".format(
                i + 1, start, start + len(text.split("\n")) - 1, text[:MAX_CONTENT_CHARS]
            )
            futures[executor.submit(_safe_generate, model, prompt, timeout, call_fn, provider)] = i

        for future in concurrent.futures.as_completed(futures):
            i = futures[future]
            try:
                result = future.result()
                summaries.append((i, result))
            except Exception as exc:
                logger.warning("Chunk %d summary failed: %s", i + 1, exc)
                summaries.append((i, "[summary failed]"))

    summaries.sort()
    return "\n".join(
        "Chunk {}: {}".format(i + 1, txt) for i, txt in summaries
    )


def _safe_generate(model, prompt, timeout, call_fn=None, provider="gemini"):
    """Generate content with retry. Returns text or empty string."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            if call_fn is not None:
                result = call_fn(model, "", "", "", "summarize", "", timeout, "")
                if isinstance(result, dict):
                    return (result.get("summary") or "").strip()
                return str(result).strip()
            # Fallback: Gemini-native path
            response = model.generate_content(
                prompt, request_options={"timeout": timeout}
            )
            return (response.text or "").strip()
        except Exception:
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
    return ""


def build_import_graph(repo_path):
    """Build a function-level call graph for cross-file reasoning.

    Scans all .py files in repo_path and returns a dict mapping:
      file_path -> {
          'imports': [module names this file imports],
          'imported_by': [file paths that import this file],
          'functions': {
              'function_name': {
                  'line': int,
                  'calls': [function names called within this function],
                  'called_by': [(file_path, function_name, line)],
              }
          }
      }

    This gives the AI "who calls whom" awareness at the function level,
    so it can reason about the blast radius of changing a specific function.
    """
    repo = Path(repo_path)
    if not repo.exists():
        return {}

    graph = {}
    py_files = list(repo.rglob("*.py"))

# First pass: collect imports and functions per file
    for py_file in py_files:
        try:
            content = py_file.read_text(errors='ignore')
            tree = ast.parse(content)
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)

            # Extract functions and their internal calls
            functions = {}
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_name = node.name
                    calls = []
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            if isinstance(child.func, ast.Name):
                                calls.append(child.func.id)
                            elif isinstance(child.func, ast.Attribute):
                                calls.append(child.func.attr)
                    functions[func_name] = {
                        'line': node.lineno,
                        'calls': list(set(calls)),
                        'called_by': [],
                    }

            graph[str(py_file)] = {
                'imports': imports,
                'imported_by': [],
                'functions': functions,
            }
        except (SyntaxError, ValueError):
            continue

    # Second pass: resolve cross-file function calls
    for py_file, info in graph.items():
        for imp in info['imports']:
            # Match import to a file in the repo. Normalize separators so
            # this works on both Windows (\) and POSIX (/).
            imp_norm = imp.replace('.', os.sep)
            for other in py_files:
                other_str = str(other)
                if other_str == py_file:
                    continue
                # Match by module path suffix (e.g. prism.agents -> prism\agents.py)
                if other_str.endswith(imp_norm + '.py') or \
                   other_str.endswith(imp_norm + os.sep + '__init__.py') or \
                   other_str.replace(os.sep, '/').endswith(imp.replace('.', '/') + '/__init__.py'):
                    if other_str not in graph:
                        graph[other_str] = {'imports': [], 'imported_by': [], 'functions': {}}
                    if py_file not in graph[other_str]['imported_by']:
                        graph[other_str]['imported_by'].append(py_file)

    # Third pass: build function-level called_by edges
    for caller_file, info in graph.items():
        for func_name, func_info in info.get('functions', {}).items():
            for called in func_info['calls']:
                # Check if called function exists in another file
                for other_file, other_info in graph.items():
                    if other_file == caller_file:
                        continue
                    if called in other_info.get('functions', {}):
                        other_info['functions'][called]['called_by'].append(
                            (caller_file, func_name, func_info['line'])
                        )

    return graph


def get_cross_file_context(file_path, graph, repo_path, max_depth=2):
    """Get cross-file context for a given file.

    Returns a string describing:
    - What this file imports (and what those modules do)
    - What files import this file (and why they might be affected)
    - Which functions in this file are called by other files (blast radius)

    This is prepended to the AI prompt so it can reason about dependencies.
    """
    if not graph:
        return ""

    file_key = str(Path(file_path).resolve())
    info = graph.get(file_key)
    if not info:
        # Try matching by suffix
        for k, v in graph.items():
            if k.endswith(str(file_path)) or str(file_path).endswith(k):
                info = v
                file_key = k
                break

    if not info:
        return ""

    parts = []

    # What this file imports
    if info.get('imports'):
        parts.append("This file imports: {}".format(", ".join(info['imports'][:10])))

    # Who imports this file
    if info.get('imported_by'):
        parts.append(
            "Files that import this file: {}".format(
                ", ".join(info['imported_by'][:5])
            )
        )

    # Function-level blast radius
    for func_name, func_info in info.get('functions', {}).items():
        called_by = func_info.get('called_by', [])
        if called_by:
            callers = []
            for cf, cf_func, cf_line in called_by[:3]:
                callers.append("{}:{}()@{}".format(
                    cf.split(os.sep)[-1].replace('.py', ''),
                    cf_func, cf_line
                ))
            parts.append(
                "Function {}() (line {}) is called by: {}".format(
                    func_name, func_info['line'], ", ".join(callers)
                )
            )

    if not parts:
        return ""

    return "\n## Cross-File Context\n" + "\n".join(parts) + "\n"

    # Who imports this file
    if info['imported_by']:
        parts.append(
            "Files that import this file: {}".format(
                ", ".join(info['imported_by'][:5])
            )
        )

    if not parts:
        return ""

    return "\n## Cross-File Context\n" + "\n".join(parts) + "\n"