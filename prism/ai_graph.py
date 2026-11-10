"""Function-level call graph for cross-file reasoning.

Scans all .py files in a repo and builds a graph mapping each file to its
imports, its dependents, and the functions it defines plus who calls them.
This gives the AI "who calls whom" awareness so it can reason about the
blast radius of changing a specific function.
"""

import os
import ast
from pathlib import Path

# Process-level cache: {repo_path: graph}.
# build_import_graph walks the whole repo on every call, which made the
# LSP server take 5.5s per file. The graph only changes when a file changes,
# so we cache it for the process lifetime and let callers invalidate it.
_graph_cache = {}


def build_import_graph(repo_path):
    """Build a function-level call graph for cross-file reasoning.

    Returns {file_path: {'imports': [...], 'imported_by': [...],
                         'functions': {name: {'line', 'calls', 'called_by'}}}}
    """
    repo = Path(repo_path)
    if not repo.exists():
        return {}

    key = str(repo.resolve())
    if key in _graph_cache:
        return _graph_cache[key]

    graph = _build_graph(repo)
    _graph_cache[key] = graph
    return graph


def invalidate_graph_cache(repo_path=None):
    """Drop the cached graph. Call from LSP on textDocument/didChange."""
    if repo_path is None:
        _graph_cache.clear()
    else:
        _graph_cache.pop(str(Path(repo_path).resolve()), None)


def _build_graph(repo):
    """Uncached graph builder. See build_import_graph for the return shape."""
    graph = {}
    py_files = list(repo.rglob("*.py"))

    # First pass: collect imports and functions per file
    for py_file in py_files:
        try:
            tree = ast.parse(py_file.read_text(errors='ignore'))
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)

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

    # Second pass: resolve cross-file imports
    for py_file, info in graph.items():
        for imp in info['imports']:
            imp_norm = imp.replace('.', os.sep)
            for other in py_files:
                other_str = str(other)
                if other_str == py_file:
                    continue
                if (other_str.endswith(imp_norm + '.py')
                        or other_str.endswith(imp_norm + os.sep + '__init__.py')):
                    graph.setdefault(other_str, {
                        'imports': [], 'imported_by': [], 'functions': {}
                    })
                    if py_file not in graph[other_str]['imported_by']:
                        graph[other_str]['imported_by'].append(py_file)

    # Third pass: build function-level called_by edges
    for caller_file, info in graph.items():
        for func_name, func_info in info.get('functions', {}).items():
            for called in func_info['calls']:
                for other_file, other_info in graph.items():
                    if other_file != caller_file and called in other_info.get('functions', {}):
                        other_info['functions'][called]['called_by'].append(
                            (caller_file, func_name, func_info['line'])
                        )

    return graph


def get_cross_file_context(file_path, graph, repo_path, max_depth=2):
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