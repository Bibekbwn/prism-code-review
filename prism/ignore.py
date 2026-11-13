"""Path exclusions for pre-commit review.

Two layers, both optional:

1. ``.prismignore`` in the repo root - one pattern per line (``#`` comments),
   using the same syntax as ``.gitignore`` (handled by ``fnmatch`` here, which
   covers the common ``*.md`` / ``docs/`` / ``!keep.py`` cases).
2. The ``ignore`` array in ``prism.json`` - for teams that prefer to keep the
   exclusion list next to the rest of the PRISM config.

The CLI ``prism ignore`` command manages layer 1, because that is the file a
developer edits by hand. Precedence: ``.prismignore`` is applied first, then
the config list, so an entry in either place excludes a path.
"""

import fnmatch
from pathlib import Path

IGNORE_FILE = ".prismignore"

# Extensions and file names that are documentation, assets, or editor noise:
# reviewing them produces findings nobody acts on, so the pre-commit hook
# skips them unless the developer explicitly opts back in.
DEFAULT_IGNORE = [
    # Documentation
    "*.md",
    "*.rst",
    "*.txt",
    "LICENSE*",
    "CHANGELOG*",
    "CONTRIBUTING*",
    "CODE_OF_CONDUCT*",
    # Assets
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.svg",
    "*.ico",
    "*.webp",
    "*.pdf",
    # Lock files and generated output
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "*.min.js",
    "*.min.css",
    # Editor / OS noise
    ".DS_Store",
    "Thumbs.db",
]


def _load_patterns(path):
    """Read patterns from a file, ignoring blanks and comments."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    patterns = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def load_patterns(config=None):
    """Return the effective ignore patterns (.prismignore + config + defaults)."""
    patterns = list(DEFAULT_IGNORE)
    patterns.extend(_load_patterns(IGNORE_FILE))
    if config:
        extra = config.get("ignore") or []
        if isinstance(extra, str):
            extra = [extra]
        patterns.extend(str(p) for p in extra if str(p).strip())
    return patterns


def _fnmatch(path, pattern):
    """Case-insensitive glob match, consistently on every platform.

    ``fnmatch.fnmatch`` normcases using the host OS, so ``*.jpg`` would match
    ``.JPG`` on Windows but not on Linux. The ignore list is written by hand,
    so a predictable rule matters more than OS-specific behaviour: compare
    lowercased on both sides.
    """
    return fnmatch.fnmatchcase(path.lower(), pattern.lower())


def _matches(path, pattern):
    """Does ``path`` match ``pattern`` (ignoring the leading '!')?

    Handles the same syntax as .gitignore for the cases that matter here:
    ``*.ext`` (basename glob), ``docs/`` (directory prefix), ``/rooted``
    (anchored), ``a/b.py`` (path glob).
    """
    path = path.replace("\\", "/").lstrip("./")
    if pattern.startswith("!"):
        pattern = pattern[1:]

    # Directory pattern: "docs/" also matches "docs/a/b.py"
    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    # No slash: match against the basename (like .gitignore)
    if "/" not in pattern:
        return _fnmatch(path.split("/")[-1], pattern)
    # Leading slash anchors to the repo root
    if pattern.startswith("/"):
        return _fnmatch(path, pattern[1:])
    # Match the full path or any trailing sub-path
    return _fnmatch(path, pattern) or _fnmatch(path, "*/" + pattern)


def is_ignored(path, patterns=None):
    """True when ``path`` should be skipped by the pre-commit review.

    Later patterns win, so a ``!keep.md`` line after ``*.md`` re-includes
    that file - the same rule .gitignore follows.
    """
    if patterns is None:
        patterns = load_patterns()
    ignored = False
    for pattern in patterns:
        if pattern.startswith("!"):
            if _matches(path, pattern):
                ignored = False
        elif _matches(path, pattern):
            ignored = True
    return ignored


def filter_files(files, patterns=None):
    """Return the subset of ``files`` that should be reviewed."""
    if patterns is None:
        patterns = load_patterns()
    kept, skipped = [], []
    for f in files:
        (skipped if is_ignored(f, patterns) else kept).append(f)
    return kept, skipped


def read_ignore_file():
    """Return the raw .prismignore lines (patterns without comments)."""
    return _load_patterns(IGNORE_FILE)


def write_ignore_file(patterns):
    """Write patterns to .prismignore, preserving nothing but the list."""
    lines = [
        "# Files PRISM skips during pre-commit review.",
        "# One pattern per line; '!' re-includes a path. See `prism help ignore`.",
        "",
    ]
    lines.extend(patterns)
    Path(IGNORE_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


def add_patterns(patterns):
    """Add patterns to .prismignore (skipping ones already present)."""
    existing = read_ignore_file()
    added = []
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern or pattern.startswith("#"):
            continue
        if pattern in existing or pattern in DEFAULT_IGNORE:
            continue
        existing.append(pattern)
        added.append(pattern)
    if added:
        write_ignore_file(existing)
    return added


def remove_patterns(patterns):
    """Remove patterns from .prismignore. Returns the ones actually removed."""
    existing = read_ignore_file()
    removed = []
    for pattern in patterns:
        pattern = pattern.strip()
        if pattern in existing:
            existing.remove(pattern)
            removed.append(pattern)
    if removed:
        write_ignore_file(existing)
    return removed


def reset_patterns():
    """Restore the built-in default ignore list."""
    write_ignore_file([])
    return list(DEFAULT_IGNORE)