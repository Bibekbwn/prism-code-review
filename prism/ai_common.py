"""Shared AI agent utilities — public API facade.

Implementation is split across:
  - ai_providers.py : provider init, API call dispatch, retry/circuit-breaker
  - ai_findings.py  : JSON parsing, finding verification, cross-check
  - ai_graph.py     : import graph and cross-file context
  - ai_pipeline.py  : chunking, tiers, two-pass summarization, review_with_agent

This module re-exports the names call sites already import so backwards
compatibility is preserved. New code should import from the submodules
directly.
"""

import logging

from prism.ai_providers import (
    get_model, API_TIMEOUT, MAX_RETRIES, MAX_CONTENT_CHARS,
)
from prism.ai_findings import parse_findings, verify_findings
from prism.ai_graph import build_import_graph, get_cross_file_context
from prism.ai_pipeline import (
    chunk_content, build_skeleton, get_tier_for_file, review_with_agent,
)

logger = logging.getLogger(__name__)

__all__ = [
    "get_model", "parse_findings", "verify_findings",
    "build_import_graph", "get_cross_file_context", "chunk_content",
    "build_skeleton", "get_tier_for_file", "review_with_agent",
    "API_TIMEOUT", "MAX_RETRIES", "MAX_CONTENT_CHARS",
]