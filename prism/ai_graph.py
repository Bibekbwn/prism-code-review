"""Function-level call graph for cross-file reasoning.

Scans all .py files in a repo and builds a graph mapping each file to its
imports, its dependents, and the functions it defines plus who calls them.
This gives the AI "who calls whom" awareness so it can reason about the
blast radius of changing a specific function.
"""

import os
import ast
from pathlib import Path

# Process-level cache: {repo_path: (signature, graph)}.
# build_import_graph walks and parses the whole repo on every call, which made
# the LSP server take 5.5s per file. The graph is reused while the repo is
# unchanged: a cheap stat signature (path, mtime, size) is compared on every
# call, so long-lived processes (LSP, watch mode) self-invalidate after edits
# without every caller having to remember to call invalidate_graph_cache().
_graph_cache = {}

# Directories that never contain first-party source worth indexing.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env",
    "node_modules", "site-packages", ".mypy_cache", ".pytest_cache",
    ".tox", "dist", "build", ".eggs",
}


def _is_skipped(path):
    return any(part in _SKIP_DIRS for part in path.parts)


def _graph_signature(py_files):
    """Stat-only fingerprint of the scanned files.

    Returns None when a file disappears mid-scan, which forces a rebuild.
    """
    signature = []
    for py_file in py_files:
        try:
            st = py_file.stat()
        except OSError:
            return None
        signature.append((str(py_file), st.st_mtime_ns, st.st_size))
    return tuple(signature)


def build_import_graph(repo_path):
    """Build a function-level call graph for cross-file reasoning.

    Returns {file_path: {'imports': [...], 'imported_by': [...],
                         'functions': {name: {'line', 'calls', 'called_by'}}}}
    """
    repo = Path(repo_path)
    if not repo.exists():
        return {}

    key = str(repo.resolve())
    py_files = [p for p in repo.rglob("*.py") if not _is_skipped(p)]
    signature = _graph_signature(py_files)

    cached = _graph_cache.get(key)
    if cached is not None and signature is not None and cached[0] == signature:
        return cached[1]

    graph = _build_graph(repo, py_files)
    _graph_cache[key] = (signature, graph)
    return graph


def invalidate_graph_cache(repo_path=None):
    """Drop the cached graph. Call from LSP on textDocument/didChange."""
    if repo_path is None:
        _graph_cache.clear()
    else:
        _graph_cache.pop(str(Path(repo_path).resolve()), None)


def _resolve_import(imp, pkg_parts):
    """Resolve an import string to a dotted module path within the repo.

    Absolute imports are returned as-is. Relative imports (stored with a
    leading-dot prefix, e.g. ``.mod`` or ``..pkg``) are resolved against the
    importing file's package parts.
    """
    if not imp:
        return None
    if not imp.startswith("."):
        return imp
    level = len(imp) - len(imp.lstrip("."))
    rest = imp[level:]
    if level > len(pkg_parts):
        return None
    base = pkg_parts[:len(pkg_parts) - (level - 1)]
    parts = list(base)
    if rest:
        parts.append(rest)
    return ".".join(parts) if parts else None


def _build_graph(repo, py_files=None):
    """Uncached graph builder. See build_import_graph for the return shape."""
    graph = {}
    if py_files is None:
        py_files = [p for p in repo.rglob("*.py") if not _is_skipped(p)]

    # First pass: collect imports and functions per file
    for py_file in py_files:
        try:
            tree = ast.parse(py_file.read_text(errors='ignore'))
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    prefix = "." * (node.level or 0)
                    imports.append(prefix + (node.module or ""))

            functions = {}
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    calls = set()
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            if isinstance(child.func, ast.Name):
                                calls.add(child.func.id)
                            elif isinstance(child.func, ast.Attribute):
                                calls.add(child.func.attr)
                    functions[node.name] = {
                        'line': node.lineno,
                        'calls': [c for c in calls if c],
                        'called_by': [],
                    }

            graph[str(py_file)] = {
                'imports': imports,
                'imported_by': [],
                'functions': functions,
            }
        except (SyntaxError, ValueError):
            continue

    # Second pass: resolve cross-file imports. Index each module by its dotted
    # path so resolution is O(1) per import (was O(imports * files)).
    module_index = {}
    for py_file in py_files:
        rel = py_file.relative_to(repo)
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        module_index[".".join(parts)] = str(py_file)

    for file_key, info in graph.items():
        py_file = Path(file_key)
        pkg_parts = list(py_file.relative_to(repo).parts[:-1])
        for imp in info['imports']:
            target = _resolve_import(imp, pkg_parts)
            if not target:
                continue
            other_str = module_index.get(target)
            if not other_str or other_str == file_key:
                continue
            other = graph.get(other_str)
            if other is None:
                continue
            if file_key not in other['imported_by']:
                other['imported_by'].append(file_key)

    # Third pass: build function-level called_by edges. Index functions by
    # name once instead of scanning every file for every call (was O(F*C*N)).
    func_index = {}
    for file_name, info in graph.items():
        for func_name, func_info in info.get("functions", {}).items():
            func_index.setdefault(func_name, []).append((file_name, func_info))

    for caller_file, info in graph.items():
        for func_name, func_info in info.get("functions", {}).items():
            for called in func_info.get("calls", []):
                for other_file, other_info in func_index.get(called, []):
                    if other_file == caller_file:
                        continue
                    other_info["called_by"].append(
                        (caller_file, func_name, func_info["line"])
                    )

    return graph


def get_cross_file_context(file_path, graph, repo_path):
    """Get cross-file context for a given file.

    Returns a string describing what this file imports, what files import
    it, and which functions are called by other files (blast radius).
    """
    if not graph:
        return ""

    info = graph.get(str(Path(file_path).resolve()))
    if not info:
        for k, v in graph.items():
            if k.endswith(str(file_path)) or str(file_path).endswith(k):
                info = v
                break
    if not info:
        return ""

    parts = []
    if info.get('imports'):
        parts.append("This file imports: {}".format(", ".join(info['imports'][:10])))
    if info.get('imported_by'):
        parts.append("Files that import this file: {}".format(
            ", ".join(info['imported_by'][:5])
        ))

    for func_name, func_info in info.get('functions', {}).items():
        for cf, cf_func, cf_line in func_info.get('called_by', [])[:3]:
            parts.append("Function {}() (line {}) is called by: {}:{}()@{}".format(
                func_name, func_info['line'],
                cf.split(os.sep)[-1].replace('.py', ''), cf_func, cf_line
            ))

    if not parts:
        return ""
    return "\n## Cross-File Context\n" + "\n".join(parts) + "\n"