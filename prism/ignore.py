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
    # --- Documentation ---
    "*.md",
    "*.markdown",
    "*.rst",
    "*.adoc",
    "*.txt",
    "*.org",
    "*.tex",
    "LICENSE*",
    "LICENCE*",
    "COPYING*",
    "NOTICE*",
    "AUTHORS*",
    "PATENTS*",
    "CHANGELOG*",
    "CHANGES*",
    "HISTORY*",
    "CONTRIBUTING*",
    "CODE_OF_CONDUCT*",
    "SECURITY*",
    # --- Images / media ---
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.bmp",
    "*.tif",
    "*.tiff",
    "*.svg",
    "*.ico",
    "*.webp",
    "*.pdf",
    "*.mp3",
    "*.mp4",
    "*.wav",
    "*.avi",
    "*.mov",
    "*.webm",
    # --- Fonts ---
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.otf",
    "*.eot",
    # --- Build output / dependencies ---
    "build/",
    "dist/",
    "out/",
    "target/",
    "bin/",
    "obj/",
    "coverage/",
    "htmlcov/",
    "node_modules/",
    "vendor/",
    "third_party/",
    "Pods/",
    ".venv/",
    "venv/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".tox/",
    "*.egg-info/",
    # --- Lock files (machine-generated) ---
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "composer.lock",
    "Gemfile.lock",
    "Cargo.lock",
    "go.sum",
    "*.lock",
    # --- Minified / generated source ---
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.pb.go",
    "*_pb2.py",
    "*_pb2_grpc.py",
    "*.designer.cs",
    "*.generated.cs",
    "*.generated.ts",
    # --- Secrets / certificates (never review, never commit) ---
    "*.pem",
    "*.key",
    "*.crt",
    "*.cer",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    # --- Data / binaries ---
    "*.zip",
    "*.tar",
    "*.gz",
    "*.tgz",
    "*.bz2",
    "*.xz",
    "*.7z",
    "*.rar",
    "*.bin",
    "*.dat",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    "*.sql",
    "*.dump",
    "*.csv",
    "*.tsv",
    "*.parquet",
    "*.xlsx",
    "*.xls",
    "*.docx",
    "*.pptx",
    # --- Editor / OS noise ---
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".idea/",
    ".vscode/",
    "*.swp",
    "*.swo",
    "*~",
    # --- PRISM's own working files ---
    ".prism-reports/",
    ".prism-cache.json",
    ".prism-feedback.json",
    "dashboard.html",
]


# Written to .prismignore on `prism ignore reset` / `prism init`. The broad
# rules already live in DEFAULT_IGNORE, so this is the short, readable set a
# developer sees when they open the file and can edit without reading 120 lines.
STARTER_IGNORE = [
    # Documentation
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    # Repo metadata that is not source
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    # Build output and dependency folders
    "build/",
    "dist/",
    "node_modules/",
    "vendor/",
    "__pycache__/",
    ".venv/",
    "coverage/",
    # Editors / OS noise
    ".vscode/",
    ".idea/",
    ".DS_Store",
    "Thumbs.db",
    # PRISM's own working files
    ".prism-reports/",
    ".prism-cache.json",
    ".prism-feedback.json",
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
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if pattern.startswith("!"):
        pattern = pattern[1:]

    # Directory pattern: "docs/" also matches "docs/a/b.py" and "pkg/docs/x"
    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        return (path == prefix
                or path.startswith(prefix + "/")
                or ("/" + prefix + "/") in ("/" + path))
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
    """Restore the starter ignore list.

    The built-in ``DEFAULT_IGNORE`` always applies on top of whatever is in
    .prismignore, so "reset" means clearing the developer's custom entries
    back to the shipped starter set (not an empty file).
    """
    write_ignore_file(list(STARTER_IGNORE))
    return list(STARTER_IGNORE)