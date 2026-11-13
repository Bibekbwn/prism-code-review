"""
Code Quality Agent - Checks complexity, cleanliness, and style.

Rule IDs follow SonarQube convention: QUAL-XXX

Thresholds are intentionally lenient. The regex pass runs on every commit, so
a strict rule set turns the pre-commit hook into a wall of warnings that
developers learn to ignore. Anything that is a style preference is LOW with
WARNS (advisory), and only a genuine complexity problem is HIGH.
"""

import ast
import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent


MAX_FUNCTION_LENGTH = 80
MAX_FILE_LENGTH = 800
COMPLEXITY_THRESHOLD = 15

# Advisory checks: reported at most once per file (first occurrence) so a
# long file cannot produce 200 identical warnings.
MAX_PER_RULE = 3

# Which checks run. Structural limits (file/function length, complexity) and
# the cheap, high-signal style checks (naming, imports) stay on; the purely
# subjective or trivially-triggered ones are off by default and opt-in via
# prism.json, e.g. {"quality": {"docstrings": true}}. These produced a wall
# of warnings developers learned to ignore.
QUALITY_DEFAULTS = {
    "file_length": True,
    "function_length": True,
    "complexity": True,
    "naming": True,
    "imports": True,
    "duplication": False,
    "todo_markers": False,
    "line_length": False,
    "magic_numbers": False,
    "docstrings": False,
    "type_hints": False,
}


def _count_lines_in_function(lines: list, start: int) -> int:
    count = 1
    indent = len(lines[start]) - len(lines[start].lstrip())
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.strip().startswith(("#", "//", "/*", "*", "*/")):
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= indent and line.strip():
            break
        count += 1
    return count


def _cyclomatic_complexity(lines: list) -> int:
    """Approximate cyclomatic complexity.

    Counts decision points rather than every `and`/`or` occurrence: the old
    version counted both plus every `if` in comments and strings, which
    inflated simple functions past the threshold.
    """
    complexity = 1
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*", "*/")):
            continue
        # Strip string literals so keywords inside text are not counted.
        code = re.sub(r'"[^"]*"|\'[^\']*\'', '""', line)
        if re.search(r'^\s*(if|elif|for|while|except|with|case)\b', code):
            complexity += 1
        elif re.search(r'\b(and|or)\b', code):
            complexity += 1
    return complexity


@register_agent
class QualityAgent(BaseAgent):
    name = "quality"
    description = "Checks code complexity, cleanliness, style, duplication, naming, imports"

    def __init__(self):
        self._enabled = dict(QUALITY_DEFAULTS)

    def _on(self, name):
        """True when the ``name`` check is enabled (default dict is lenient)."""
        return bool(self._enabled.get(name, QUALITY_DEFAULTS.get(name, False)))

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")

        if self._on("file_length") and len(lines) > MAX_FILE_LENGTH:
            findings.append(Finding(
                agent=self.name,
                severity=Severity.LOW,
                category="File Length",
                message="File has {} lines (max {})".format(len(lines), MAX_FILE_LENGTH),
                file=file_path,
                suggestion="Consider splitting into smaller modules.",
                blocker=Blocker.WARNS,
                confidence=1.0,
                rule_id="QUAL-101",
            ))

        func_starts = []
        for i, line in enumerate(lines):
            if re.match(r'^\s*(def |function |async def |public |private |protected )', line):
                func_starts.append(i)

        for start in func_starts:
            func_lines = _count_lines_in_function(lines, start)
            func_content = "\n".join(lines[start:start + func_lines])
            complexity = _cyclomatic_complexity(func_content)

            if self._on("function_length") and func_lines > MAX_FUNCTION_LENGTH:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.LOW,
                    category="Function Length",
                    message="Function at line {} has {} lines (max {})".format(
                        start + 1, func_lines, MAX_FUNCTION_LENGTH),
                    file=file_path,
                    line=start + 1,
                    suggestion="Consider breaking into smaller helpers.",
                    blocker=Blocker.WARNS,
                    confidence=1.0,
                    rule_id="QUAL-102",
                ))

            if self._on("complexity") and complexity > COMPLEXITY_THRESHOLD:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    category="Complexity",
                    message="Function at line {} has complexity {} (max {})".format(
                        start + 1, complexity, COMPLEXITY_THRESHOLD),
                    file=file_path,
                    line=start + 1,
                    suggestion="Reduce branching. Use early returns, lookup tables, or strategy pattern.",
                    blocker=Blocker.WARNS,
                    confidence=0.90,
                    rule_id="QUAL-103",
                ))

        if self._on("todo_markers"):
            findings.extend(_cap(_check_incomplete_markers(lines, file_path),
                                 "QUAL-104"))
        if self._on("line_length"):
            findings.extend(_cap(_check_line_length(lines, file_path), "QUAL-105"))

        # Advisory checks, each capped per file (see _cap).
        if self._on("duplication"):
            findings.extend(_cap(_check_duplication(content, file_path), "QUAL-106", 3))
        if self._on("naming"):
            findings.extend(_cap(_check_naming(content, file_path), "QUAL-107"))
        if self._on("imports"):
            findings.extend(_cap(_check_imports(content, file_path), "QUAL-108"))
        if self._on("magic_numbers"):
            findings.extend(_cap(_check_magic_numbers(content, file_path), "QUAL-109"))
        if self._on("docstrings"):
            findings.extend(_cap(_check_missing_docstrings(content, file_path), "QUAL-110"))
        if self._on("type_hints"):
            findings.extend(_cap(_check_missing_type_hints(content, file_path), "QUAL-111"))

        return findings


def _cap(findings, rule_id, limit=MAX_PER_RULE):
    """Keep at most ``limit`` findings per rule id.

    A 900-line file used to emit one warning per TODO, per long line and per
    missing annotation. Three examples are enough to make the point; the rest
    is noise the developer scrolls past.
    """
    kept = []
    seen = 0
    for f in findings:
        if f.rule_id == rule_id:
            if seen >= limit:
                continue
            seen += 1
        kept.append(f)
    return kept


def _check_incomplete_markers(lines, file_path):
    """Report TODO/FIXME/HACK/XXX markers (capped per file)."""
    findings = []
    for i, line in enumerate(lines):
        if len(findings) >= MAX_PER_RULE:
            break
        match = re.search(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', line)
        if match:
            findings.append(Finding(
                agent="quality",
                severity=Severity.LOW,
                category="Incomplete Code",
                message="Found '{}' marker".format(match.group(1)),
                file=file_path,
                line=i + 1,
                suggestion="Resolve before committing.",
                blocker=Blocker.WARNS,
                confidence=1.0,
                rule_id="QUAL-104",
            ))
    return findings


def _check_line_length(lines, file_path):
    """Report lines over 120 characters (capped per file)."""
    findings = []
    for i, line in enumerate(lines):
        if len(findings) >= MAX_PER_RULE:
            break
        if len(line) > 120:
            findings.append(Finding(
                agent="quality",
                severity=Severity.LOW,
                category="Line Length",
                message="Line {} has {} characters (max 120)".format(i + 1, len(line)),
                file=file_path,
                line=i + 1,
                suggestion="Break long lines for readability.",
                blocker=Blocker.WARNS,
                confidence=1.0,
                rule_id="QUAL-105",
            ))
    return findings


def _check_magic_numbers(content: str, file_path: str) -> List[Finding]:
    """Flag hardcoded numeric constants used in non-trivial contexts.

    Only flags numbers that appear in comparisons, arithmetic, indexing,
    or function-call arguments — not bare loop counters like `i = 0`
    or `x = 1`. This avoids the false-positive storm that pure literal
    scanning produces (e.g. one 9000-line file producing 8000+ findings).
    """
    if not file_path.endswith(".py"):
        return []
    findings = []
    lines = content.split("\n")
    allowed = {"0", "1", "2", "3", "-1", "0.0", "1.0", "100", "1000",
               "1024", "3600", "60", "300", "8080", "3000", "5000",
               "0.5", "0.25", "0.8", "0.95", "255", "128", "64", "32",
               "24", "48", "72", "96", "100", "200", "400", "500", "1000",
               "0.1", "0.2", "0.3", "0.4", "0.6", "0.7", "0.9"}
    # Match a 2+ digit literal that is NOT the sole RHS of a `name =` assignment.
    # The negative lookahead rejects `foo = 123` and `i += 1` counters.
    pattern = re.compile(
        r'(?<![\w.])(\d{2,})(?![\w.])'
    )
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith(("import ", "from ")):
            continue
        # Skip bare assignment lines where the number is the only RHS value
        # (loop counters, list seeding). Still check lines with operators.
        if "=" in line and not any(op in line for op in ("==", "!=", "<=", ">=", "+", "-", "*", "/", "%", "[", "(", ",")):
            continue
        for match in pattern.finditer(line):
            num = match.group(1)
            if num in allowed:
                continue
            findings.append(Finding(
                agent="quality",
                severity=Severity.LOW,
                category="Magic Number",
                message="Magic number '{}' on line {}".format(num, i + 1),
                file=file_path,
                line=i + 1,
                suggestion="Consider a named constant if this value carries meaning.",
                blocker=Blocker.WARNS,
                confidence=0.40,
                rule_id="QUAL-109",
            ))
    return findings


def _check_missing_docstrings(content: str, file_path: str) -> List[Finding]:
    """Flag public functions/classes without docstrings."""
    if not file_path.endswith(".py"):
        return []
    findings = []
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return findings

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("_"):
                continue
            body = node.body
            has_docstring = (
                len(body) > 0 and
                isinstance(body[0], ast.Expr) and
                isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            )
            if not has_docstring:
                findings.append(Finding(
                    agent="quality",
                    severity=Severity.LOW,
                    category="Missing Docstring",
                    message="{} '{}' has no docstring".format(
                        "Class" if isinstance(node, ast.ClassDef) else "Function",
                        node.name),
                    file=file_path,
                    line=node.lineno,
                    suggestion="Add a docstring describing purpose, params, and return.",
                    blocker=Blocker.WARNS,
                    confidence=0.85,
                    rule_id="QUAL-110",
                ))
    return findings


def _check_missing_type_hints(content: str, file_path: str) -> List[Finding]:
    """Flag public functions without return type annotations."""
    if not file_path.endswith(".py"):
        return []
    findings = []
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return findings

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            if node.returns is None:
                findings.append(Finding(
                    agent="quality",
                    severity=Severity.LOW,
                    category="Missing Type Hint",
                    message="Function '{}' has no return type annotation".format(node.name),
                    file=file_path,
                    line=node.lineno,
                    suggestion="Add a return type annotation.",
                    blocker=Blocker.WARNS,
                    confidence=0.75,
                    rule_id="QUAL-111",
                ))
    return findings


def _check_duplication(content: str, file_path: str) -> List[Finding]:
    """Detect code duplication (4+ lines repeated).

    Capped at 20 findings per file to avoid the false-positive storm that
    short repeated blocks produce (e.g. a CLI with many `print("  [x] ...")`
    lines would otherwise generate 100+ findings).
    """
    findings = []
    lines = [l.strip() for l in content.split("\n") if l.strip()]
    seen = {}
    for i in range(len(lines)):
        if len(findings) >= 20:
            break
        for length in range(4, min(8, len(lines) - i + 1)):
            block = "\n".join(lines[i:i + length])
            if block in seen:
                findings.append(Finding(
                    agent="quality",
                    severity=Severity.MEDIUM,
                    category="Duplication",
                    message="Duplicate block ({} lines) at line {}".format(
                        length, seen[block] + 1),
                    file=file_path,
                    line=i + 1,
                    suggestion="Extract repeated code into a function.",
                    blocker=Blocker.WARNS,
                    confidence=0.85,
                    rule_id="QUAL-106",
                ))
                break
            else:
                seen[block] = i
    return findings


def _check_naming(content: str, file_path: str) -> List[Finding]:
    """Check naming conventions."""
    findings = []
    lines = content.split("\n")

    for i, line in enumerate(lines):
        if file_path.endswith(".py"):
            # Check for CamelCase variables (not class/function names)
            # Valid: snake_case_with_underscores or single_word
            # Invalid: camelCase or PascalCase variables
            match = re.match(r'^(\s*)([a-zA-Z_]\w*)\s*=\s*', line)
            if match:
                var_name = match.group(2)
                # Skip dunder and single underscore prefixes
                if var_name.startswith("__") or var_name.startswith("_"):
                    continue
                # Check for camelCase (lowercase start, then uppercase inside)
                if re.match(r'^[a-z]+[A-Z]', var_name):
                    findings.append(Finding(
                        agent="quality",
                        severity=Severity.LOW,
                        category="Naming Convention",
                        message="Variable '{}' should be snake_case, not camelCase".format(var_name),
                        file=file_path,
                        line=i + 1,
                        suggestion="Use snake_case for variable names.",
                        blocker=Blocker.WARNS,
                        confidence=0.80,
                        rule_id="QUAL-107",
                    ))
        elif file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
            match = re.match(r'^(\s*)(var|let|const)\s+(\w+)', line)
            if match:
                var_name = match.group(3)
                if "_" in var_name and not var_name.startswith("_"):
                    findings.append(Finding(
                        agent="quality",
                        severity=Severity.LOW,
                        category="Naming Convention",
                        message="Variable '{}' should be camelCase, not snake_case".format(var_name),
                        file=file_path,
                        line=i + 1,
                        suggestion="Use camelCase for variable names.",
                        blocker=Blocker.WARNS,
                        confidence=0.80,
                        rule_id="QUAL-107",
                    ))

    return findings


def _check_imports(content: str, file_path: str) -> List[Finding]:
    """Check import ordering and unused imports."""
    findings = []
    lines = content.split("\n")

    # Strip comments and strings to avoid false positives
    code_lines = []
    for line in lines:
        # Remove inline comments
        in_string = False
        string_char = None
        cleaned = []
        i = 0
        while i < len(line):
            ch = line[i]
            if not in_string and ch in ('"', "'"):
                in_string = True
                string_char = ch
                cleaned.append(" ")
            elif in_string and ch == string_char:
                in_string = False
                cleaned.append(" ")
            elif in_string:
                cleaned.append(" ")
            elif ch == "#":
                break  # rest of line is comment
            else:
                cleaned.append(ch)
            i += 1
        code_lines.append("".join(cleaned))

    code_content = "\n".join(code_lines)

    imports = []
    for i, line in enumerate(lines):
        if re.match(r'^\s*(import |from )', line):
            imports.append((i, line.strip()))

    for i, imp_line in imports:
        if file_path.endswith(".py"):
            # Handle: import module
            match = re.match(r'^import (\w+)', imp_line)
            if match:
                module = match.group(1)
                usage_count = code_content.count(module)
                if usage_count <= 1:
                    findings.append(Finding(
                        agent="quality",
                        severity=Severity.LOW,
                        category="Unused Import",
                        message="Import '{}' may be unused".format(module),
                        file=file_path,
                        line=i + 1,
                        suggestion="Remove unused import.",
                        blocker=Blocker.WARNS,
                        confidence=0.70,
                        rule_id="QUAL-108",
                    ))
            # Handle: from module import name
            match = re.match(r'^from (\w+) import', imp_line)
            if match:
                module = match.group(1)
                # Check if imported names are used, not just the module name
                # Extract imported names: from module import name1, name2
                names_match = re.search(r'import\s+(.+)$', imp_line)
                if names_match:
                    names_str = names_match.group(1)
                    # Split by comma, handle "module as alias"
                    imported_names = []
                    for part in names_str.split(","):
                        part = part.strip()
                        # Handle "name as alias"
                        name = re.split(r'\s+as\s+', part)[0].strip()
                        if name:
                            imported_names.append(name)
                    # Check if any imported name is used in code
                    any_used = False
                    for name in imported_names:
                        if code_content.count(name) > 1:
                            any_used = True
                            break
                    if not any_used and imported_names:
                        findings.append(Finding(
                            agent="quality",
                            severity=Severity.LOW,
                            category="Unused Import",
                            message="Import from '{}' may be unused".format(module),
                            file=file_path,
                            line=i + 1,
                            suggestion="Remove unused import.",
                            blocker=Blocker.WARNS,
                            confidence=0.70,
                            rule_id="QUAL-108",
                        ))

    return findings