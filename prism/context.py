"""
AST-guided context extraction.

Extracts only the functions, classes, and lines around findings
to reduce token usage and improve AI review accuracy.

Based on: "Grounding first, then generate" pattern from
production AI code review research.
"""

import re
import ast
from typing import List, Dict, Tuple, Optional


def extract_context(content: str, target_lines: List[int], window: int = 5) -> str:
    """
    Extract code context around target line numbers.

    Args:
        content: Full file content
        target_lines: Line numbers of findings
        window: Lines of context around each finding

    Returns:
        Trimmed content with only relevant sections
    """
    lines = content.split("\n")
    if not target_lines:
        return content

    # Get function/class boundaries for each target line
    ranges = _get_function_ranges(lines, target_lines)

    # Collect unique line ranges
    seen = set()
    result_lines = []

    for start, end in ranges:
        start = max(0, start - window)
        end = min(len(lines), end + window)
        for i in range(start, end):
            if i not in seen:
                seen.add(i)
                result_lines.append((i, lines[i]))

    if not result_lines:
        return content

    result_lines.sort(key=lambda x: x[0])
    output = []
    prev = -2
    for i, line in result_lines:
        if i > prev + 1:
            if output:
                output.append("...")
        output.append("{}: {}".format(i + 1, line))
        prev = i

    return "\n".join(output)


def _get_function_ranges(lines: List[str], target_lines: List[int]) -> List[Tuple[int, int]]:
    """Find function/class boundaries containing target lines."""
    ranges = []
    targets = set(target_lines)

    # Find function/class start lines
    func_starts = []
    for i, line in enumerate(lines):
        if re.match(r'^\s*(def |function |async def |class )', line):
            func_starts.append(i)

    for start in func_starts:
        end = _find_func_end(lines, start)
        # Check if any target line falls within this function
        if any(start <= t <= end for t in targets):
            ranges.append((start, end))

    # If no functions found, use whole file
    if not ranges:
        ranges.append((0, len(lines) - 1))

    return ranges


def _find_func_end(lines: List[str], start: int) -> int:
    """Find the end line of a function/class starting at `start`."""
    indent = len(lines[start]) - len(lines[start].lstrip())
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= indent:
            return i - 1
    return len(lines) - 1


def extract_for_findings(content: str, findings: List) -> str:
    """Extract context for a list of Finding objects."""
    target_lines = [f.line for f in findings if f.line is not None]
    return extract_context(content, target_lines)


def get_ast_summary(content: str) -> Dict:
    """Get a summary of the AST structure (functions, classes, imports)."""
    summary = {"functions": [], "classes": [], "imports": []}
    lines = content.split("\n")

    for i, line in enumerate(lines):
        if re.match(r'^\s*(import |from )', line):
            summary["imports"].append(line.strip())
        elif re.match(r'^\s*def (\w+)', line):
            name = re.search(r'def (\w+)', line)
            if name:
                summary["functions"].append({"name": name.group(1), "line": i + 1})
        elif re.match(r'^\s*class (\w+)', line):
            name = re.search(r'class (\w+)', line)
            if name:
                summary["classes"].append({"name": name.group(1), "line": i + 1})

    return summary