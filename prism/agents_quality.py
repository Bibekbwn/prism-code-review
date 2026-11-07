"""
Code Quality Agent - Checks complexity, cleanliness, and style.

Rule IDs follow SonarQube convention: QUAL-XXX
"""

import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent


MAX_FUNCTION_LENGTH = 50
MAX_FILE_LENGTH = 500
COMPLEXITY_THRESHOLD = 10


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
    complexity = 1
    for line in lines:
        if re.search(r'\b(if|elif|else\s+if|for|while|except|and|or)\b', line):
            complexity += 1
    return complexity


@register_agent
class QualityAgent(BaseAgent):
    name = "quality"
    description = "Checks code complexity, cleanliness, style, duplication, naming, imports"

    def _check(self, file_path: str, content: str, diff: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")

        if len(lines) > MAX_FILE_LENGTH:
            findings.append(Finding(
                agent=self.name,
                severity=Severity.MEDIUM,
                category="File Length",
                message="File has {} lines (max {})".format(len(lines), MAX_FILE_LENGTH),
                file=file_path,
                suggestion="Split into smaller modules.",
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

            if func_lines > MAX_FUNCTION_LENGTH:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.MEDIUM,
                    category="Function Length",
                    message="Function at line {} has {} lines (max {})".format(
                        start + 1, func_lines, MAX_FUNCTION_LENGTH),
                    file=file_path,
                    line=start + 1,
                    suggestion="Break into smaller helper functions.",
                    blocker=Blocker.WARNS,
                    confidence=1.0,
                    rule_id="QUAL-102",
                ))

            if complexity > COMPLEXITY_THRESHOLD:
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    category="Complexity",
                    message="Function at line {} has complexity {} (max {})".format(
                        start + 1, complexity, COMPLEXITY_THRESHOLD),
                    file=file_path,
                    line=start + 1,
                    suggestion="Reduce branching. Use early returns, lookup tables, or strategy pattern.",
                    blocker=Blocker.BLOCKS,
                    confidence=0.90,
                    rule_id="QUAL-103",
                ))

        for i, line in enumerate(lines):
            match = re.search(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', line)
            if match:
                findings.append(Finding(
                    agent=self.name,
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

        for i, line in enumerate(lines):
            if len(line) > 120:
                findings.append(Finding(
                    agent=self.name,
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

        # New lint checks
        findings.extend(_check_duplication(content, file_path))
        findings.extend(_check_naming(content, file_path))
        findings.extend(_check_imports(content, file_path))

        return findings


def _check_duplication(content: str, file_path: str) -> List[Finding]:
    """Detect code duplication (3+ lines repeated)."""
    findings = []
    lines = [l.strip() for l in content.split("\n") if l.strip()]
    seen = {}
    for i in range(len(lines)):
        for length in range(3, min(10, len(lines) - i + 1)):
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

    # Strip comments only — preserve strings to avoid false positives
    code_lines = []
    for line in lines:
        in_string = False
        string_char = None
        cleaned = []
        i = 0
        while i < len(line):
            ch = line[i]
            if not in_string and ch in ('"', "'"):
                in_string = True
                string_char = ch
                cleaned.append(ch)
            elif in_string and ch == string_char:
                in_string = False
                cleaned.append(ch)
            elif in_string:
                cleaned.append(ch)
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
                # Check for module usage as standalone word OR as module.something
                usage_pattern = re.compile(r'\b' + re.escape(module) + r'\b')
                usage_count = len(usage_pattern.findall(code_content))
                # Also check for module.something usage
                dotted_usage = code_content.count(module + ".")
                total_usage = usage_count + dotted_usage
                if total_usage <= 1:
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
                        usage_pattern = re.compile(r'\b' + re.escape(name) + r'\b')
                        usage_count = len(usage_pattern.findall(code_content))
                        if usage_count > 1:
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