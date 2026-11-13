"""Chunking, file-size tiers, two-pass summarization, and the review pipeline.

This module owns the file-size adaptation logic (single call vs chunked vs
two-pass) and the top-level `review_with_agent` entry point used by every
AI agent. It depends on `ai_providers` for the LLM client and `ai_findings`
for parsing/verification.
"""

import os
import time
import logging
import concurrent.futures

from prism.ai_providers import get_model, API_TIMEOUT
from prism.ai_findings import parse_findings, verify_findings, _AGENT_PREFIX
from prism.agents import Finding, Severity, Blocker

logger = logging.getLogger(__name__)

CHUNK_OVERLAP = 20


def _error_finding(agent_name, file_path, message, blocking=False):
    """Surface an AI failure as a visible finding.

    Silently returning [] made a failed agent look like a clean review. A
    provider outage (transport error, 504, invalid JSON) is blocking: letting
    it pass means the gate reports "clean" for a review that never happened.
    A missing API key is not an outage -- it is an unconfigured install -- so
    it stays non-blocking and only bites when AI review was requested.
    """
    prefix = _AGENT_PREFIX.get(agent_name, agent_name.upper()[:4])
    return Finding(
        agent=agent_name,
        severity=Severity.HIGH if blocking else Severity.LOW,
        category="AI Error",
        message=message,
        file=file_path,
        line=None,
        suggestion="Check the provider, API key, and network, then re-run.",
        blocker=Blocker.BLOCKS if blocking else Blocker.ALLOWS,
        confidence=1.0,
        rule_id="{}-AI-ERR".format(prefix),
    )


def _failed_message(result):
    """Return (error, blocking) if the provider call failed, else (None, False).

    A provider outage -- transport error, timeout, open circuit -- blocks:
    the review never happened, so "no findings" would be a lie. A model that
    answered with prose instead of JSON is a formatting problem, not an
    outage; retrying already happened, and one chatty chunk must not fail an
    otherwise clean review.
    """
    if isinstance(result, dict) and result.get("_failed"):
        message = str(result.get("_error") or result.get("summary") or "unknown error")
        blocking = result.get("_error_kind") != "invalid_json"
        return message, blocking
    return None, False

# File-size tiers: (threshold_lines, timeout_multiplier, whole_file_agents)
TIERS = [
    (400, 1.0, []),
    (2000, 1.5, ["ai_test", "ai_policy"]),
    (10000, 2.0, ["ai_test", "ai_policy", "ai_security", "ai_performance"]),
    (999999, 3.0, ["ai_test", "ai_policy", "ai_security", "ai_performance", "ai_quality"]),
]


def get_tier_for_file(line_count):
    """Return (timeout_multiplier, whole_file_agents) for a file of given line count."""
    for threshold, multiplier, whole_file in TIERS:
        if line_count <= threshold:
            return multiplier, whole_file
    return TIERS[-1][1], TIERS[-1][2]


def chunk_content(content, max_lines=400, overlap=20):
    """Split content into overlapping chunks. Returns list of (start_line, chunk_text)."""
    lines = content.split("\n")
    if len(lines) <= max_lines:
        return [(1, content)]

    chunks = []
    start = 0
    while start < len(lines):
        end = min(start + max_lines, len(lines))
        chunks.append((start + 1, "\n".join(lines[start:end])))
        if end >= len(lines):
            break
        start = end - overlap
    return chunks


def build_skeleton(file_path, content):
    """Extract a compact structural summary from Python source.

    Returns a skeleton showing imports, classes, functions, and line numbers.
    Non-Python files return an empty string.
    """
    import ast
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
            imports.extend(a.name for a in node.names)
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
            skeleton.append("Class {} (line {})".format(node.name, node.lineno))
            for m in methods:
                skeleton.append("  - {}".format(m))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            skeleton.append("Function {} (line {})".format(node.name, node.lineno))
    return "\n".join(skeleton)


def review_with_agent(system_prompt, file_path, content, agent_name,
                      skeleton="", line_count=None, diff="", fast=False):
    """Full pipeline: get model, call LLM, parse findings, verify.

    Uses `diff` (git diff hunks) when available; falls back to full content.
    Adapts to file size via TIERS. When `fast=True`, whole-file agents use
    two-pass summarization instead of running on every chunk.
    """
    model, provider, call_fn = get_model()
    if model is None:
        logger.info("%s skipped: no API key for provider", agent_name)
        return [_error_finding(agent_name, file_path,
                               "no API key configured for provider")]

    if line_count is None:
        line_count = content.count("\n") + 1

    review_content = diff if diff and diff.strip() else content
    if diff and diff.strip():
        line_count = review_content.count("\n") + 1

    repo_path = os.getenv("PRISM_REPO_PATH", os.getcwd())
    from prism.ai_graph import build_import_graph, get_cross_file_context
    graph = build_import_graph(repo_path)
    cross_file_context = get_cross_file_context(file_path, graph, repo_path)

    tier_multiplier, whole_file_agents = get_tier_for_file(line_count)
    needs_whole_file = agent_name in whole_file_agents

    timeout = min(120, int(API_TIMEOUT * tier_multiplier))
    env_timeout = os.getenv("PRISM_TIMEOUT")
    if env_timeout:
        try:
            timeout = int(env_timeout)
        except ValueError:
            pass

    try:
        chunks = chunk_content(content)
        if len(chunks) == 1:
            result = call_fn(model, system_prompt, file_path,
                             content, agent_name, skeleton, timeout, cross_file_context)
            error, blocking = _failed_message(result)
            if error:
                logger.error("%s failed: %s", agent_name, error)
                return [_error_finding(agent_name, file_path,
                                       "{} failed: {}".format(agent_name, error),
                                       blocking=blocking)]
            raw = parse_findings(result, file_path, agent_name)
            return verify_findings(raw, file_path, content)

        if needs_whole_file and fast:
            logger.info(
                "%s: whole-file agent, summarizing %d chunks first "
                "(%d-line file, timeout=%ds)",
                agent_name, len(chunks), line_count, timeout
            )
            summaries = _summarize_chunks(
                model, chunks, file_path, skeleton, timeout, call_fn, provider
            )
            prompt_content = "## Chunk Summaries\n{}".format(summaries)
            result = call_fn(
                model, system_prompt, file_path,
                prompt_content, agent_name, skeleton, timeout, cross_file_context,
            )
            error, blocking = _failed_message(result)
            if error:
                logger.error("%s failed: %s", agent_name, error)
                return [_error_finding(agent_name, file_path,
                                       "{} failed: {}".format(agent_name, error),
                                       blocking=blocking)]
            raw = parse_findings(result, file_path, agent_name)
            return verify_findings(raw, file_path, content)

        logger.info(
            "%s: %d-line file split into %d chunks (timeout=%ds)",
            agent_name, line_count, len(chunks), timeout
        )
        all_findings = []
        chunk_failed = None
        for chunk_start, chunk_text in chunks:
            chunk_skeleton = skeleton if skeleton else ""
            result = call_fn(
                model, system_prompt, file_path,
                chunk_text, agent_name, chunk_skeleton, timeout, cross_file_context,
            )
            error, blocking = _failed_message(result)
            if error:
                logger.error("%s chunk at line %d failed: %s",
                             agent_name, chunk_start, error)
                if chunk_failed is None:
                    chunk_failed = (error, blocking)
                continue
            findings = parse_findings(result, file_path, agent_name)
            for f in findings:
                if f.line:
                    f.line = f.line + chunk_start - 1
            all_findings.extend(findings)

        if chunk_failed and not all_findings:
            error, blocking = chunk_failed
            return [_error_finding(agent_name, file_path,
                                   "{} failed: {}".format(agent_name, error),
                                   blocking=blocking)]

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
        return [_error_finding(agent_name, file_path,
                               "{} pipeline failed: {}".format(agent_name, exc),
                               blocking=True)]


def _summarize_chunks(model, chunks, file_path, skeleton, timeout, call_fn=None, provider="gemini"):
    """Summarize each chunk in parallel. Returns a compressed string."""
    summary_prompt = (
        "Summarize this code chunk in 1-2 sentences. "
        "Focus on: what functions/classes exist, what they do, "
        "and any notable patterns (security, performance, policy). "
        'Return ONLY JSON of the form {"summary": "..."}.\n\n'
    )
    if skeleton:
        summary_prompt += "File structure:\n{}\n\n".format(skeleton)

    summaries = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for i, (start, text) in enumerate(chunks):
            prompt = summary_prompt + "Chunk {} (lines {}-{})\n{}".format(
                i + 1, start, start + len(text.split("\n")) - 1, text[:16000]
            )
            futures[executor.submit(_safe_generate, model, prompt, timeout, call_fn, provider)] = i

        for future in concurrent.futures.as_completed(futures):
            i = futures[future]
            try:
                summaries.append((i, future.result()))
            except Exception as exc:
                logger.warning("Chunk %d summary failed: %s", i + 1, exc)
                summaries.append((i, "[summary failed]"))

    summaries.sort()
    return "\n".join(
        "Chunk {}: {}".format(i + 1, txt) for i, txt in summaries
    )


def _safe_generate(model, prompt, timeout, call_fn=None, provider="gemini"):
    """Generate content with retry. Returns text or empty string."""
    for attempt in range(4):
        try:
            if call_fn is not None:
                # Pass the prompt as the content argument; the provider
                # dispatch builds the final request from it.
                result = call_fn(model, "", "", prompt, "summarize", "", timeout, "")
                if isinstance(result, dict):
                    return (result.get("summary") or "").strip()
                return str(result).strip()
            response = model.generate_content(prompt, request_options={"timeout": timeout})
            return (response.text or "").strip()
        except Exception:
            if attempt < 3:
                time.sleep(2 ** attempt)
    return ""