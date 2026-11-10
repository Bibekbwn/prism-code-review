"""
Codebase cache — avoids re-reviewing unchanged files across commits.

Provides:
  get_changed_files()  -> (changed, unchanged, cache)
  get_cached_findings(file_path, cache) -> list or None
  cache_findings(file_path, findings, cache) -> None
  get_cache_stats() -> dict
  clear_cache() -> int

The cache lives in .prism-cache.json at the repo root. It stores a SHA-256
of each reviewed file's content, so unchanged files skip the AI review
entirely on subsequent commits.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path

CACHE_FILE = ".prism-cache.json"


def _repo_root():
    """Find the git repo root, falling back to cwd."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0 and r.stdout.strip():
            return Path(r.stdout.strip())
    except Exception:
        pass
    return Path(os.getcwd())


def _cache_path():
    return _repo_root() / CACHE_FILE


def _load_cache():
    """Load the cache from disk. Returns {} on any error."""
    try:
        p = _cache_path()
        if p.exists():
            with open(p) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_cache(cache):
    """Persist the cache to disk."""
    try:
        with open(_cache_path(), "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def _file_sha(path):
    """SHA-256 of file contents, or None if unreadable."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def get_changed_files():
    """Return (changed, unchanged, cache).

    changed:    list of file paths whose content hash differs from last review
    unchanged:  list of file paths whose content hash matches (cached)
    cache:      dict of {file_path: {"sha": hash, "findings": [...]}}
    """
    cache = _load_cache()
    root = _repo_root()

    # Get all tracked files
    try:
        r = subprocess.run(
            ["git", "ls-files"],
            capture_output=True, text=True, timeout=10, cwd=str(root)
        )
        if r.returncode != 0:
            return [], [], cache
        all_files = [f.strip() for f in r.stdout.split("\n") if f.strip()]
    except Exception:
        return [], [], cache

    # Never cache the cache file itself or report artifacts
    skip = {CACHE_FILE, "prism.json", ".env", ".env.example"}
    all_files = [f for f in all_files if os.path.basename(f) not in skip]

    changed = []
    unchanged = []
    for f in all_files:
        fpath = root / f
        sha = _file_sha(fpath)
        if sha is None:
            continue
        cached = cache.get(f, {})
        # Check for the "findings" key explicitly — an empty list [] is a
        # valid cache entry (file reviewed, no findings) but is falsy, so
        # using `if cached.get("findings")` would never cache clean files.
        if cached.get("sha") == sha and "findings" in cached:
            unchanged.append(f)
        else:
            changed.append(f)
            # Update the sha so cache_findings has the right value
            cache.setdefault(f, {})["sha"] = sha

    return changed, unchanged, cache


def get_cached_findings(file_path, cache):
    """Return cached findings for a file, or None if not cached."""
    entry = cache.get(file_path, {})
    findings = entry.get("findings")
    if findings is None:
        return None
    return findings


def cache_findings(file_path, findings, cache):
    """Store findings for a file in the cache."""
    cache.setdefault(file_path, {})["findings"] = findings
    _save_cache(cache)


def get_cache_stats():
    """Return cache statistics."""
    cache = _load_cache()
    return {
        "files_cached": len(cache),
        "cache_file": str(_cache_path()),
        "exists": _cache_path().exists(),
    }


def clear_cache():
    """Delete the cache file. Returns number of entries cleared."""
    cache = _load_cache()
    count = len(cache)
    try:
        p = _cache_path()
        if p.exists():
            p.unlink()
    except Exception:
        pass
    return count