"""
Codebase-wide analysis cache.

Stores a fingerprint of each file so that on subsequent runs,
only changed files are rescanned. This avoids scanning the
entire codebase every time.

How it works:
1. First run: scans all files, stores hashes + findings
2. Subsequent runs: only scans files whose hash changed
3. Old findings for unchanged files are reused

This is similar to how production tools like CodeRabbit work.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CACHE_DIR = ".prism-cache"
CACHE_INDEX = os.path.join(CACHE_DIR, "index.json")


def _ensure_dir():
    Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)


def _file_hash(content: str) -> str:
    """Generate a hash for file content."""
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _get_codebase_files(root: str = ".", extensions: tuple = (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".c", ".cpp", ".rs")) -> List[str]:
    """Get all source files in the codebase, excluding common ignore dirs."""
    ignore_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache", ".prism-cache", ".prism-reports", "dist", "build", ".next"}
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for f in filenames:
            if f.endswith(extensions):
                files.append(os.path.join(dirpath, f))
    return sorted(files)


def load_cache() -> Dict:
    """Load the codebase cache index."""
    if os.path.exists(CACHE_INDEX):
        try:
            with open(CACHE_INDEX) as f:
                return json.load(f)
        except Exception:
            pass
    return {"files": {}, "last_scan": None}


def save_cache(cache: Dict):
    """Save the codebase cache index."""
    _ensure_dir()
    with open(CACHE_INDEX, "w") as f:
        json.dump(cache, f, indent=2)


def get_changed_files(root: str = ".") -> Tuple[List[str], List[str], Dict]:
    """
    Compare current files against cache.
    
    Returns:
        (changed_files, unchanged_files, cache)
    """
    cache = load_cache()
    current_files = _get_codebase_files(root)
    
    current_hashes = {}
    changed = []
    unchanged = []
    
    for filepath in current_files:
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
            file_hash = _file_hash(content)
            current_hashes[filepath] = file_hash
            
            cached = cache.get("files", {}).get(filepath)
            if cached is None:
                changed.append(filepath)
            elif isinstance(cached, dict):
                if cached.get("hash") != file_hash:
                    changed.append(filepath)
                else:
                    unchanged.append(filepath)
            elif cached == file_hash:
                unchanged.append(filepath)
            else:
                changed.append(filepath)
        except Exception:
            changed.append(filepath)
    
    # Update cache - preserve existing findings, update hashes
    for filepath, file_hash in current_hashes.items():
        existing = cache.get("files", {}).get(filepath, {})
        if isinstance(existing, dict):
            cache["files"][filepath] = {**existing, "hash": file_hash}
        else:
            cache["files"][filepath] = {"hash": file_hash}
    
    cache["last_scan"] = __import__("datetime").datetime.now().isoformat()
    save_cache(cache)
    
    return changed, unchanged, cache


def get_cached_findings(filepath: str, cache: Dict) -> Optional[List[dict]]:
    """Get cached findings for a file if it hasn't changed.
    
    Returns None if no cached findings exist for this file.
    """
    cached = cache.get("files", {}).get(filepath)
    if cached is None:
        return None
    # If cached value is a dict with findings, return them
    if isinstance(cached, dict) and cached.get("findings"):
        return cached["findings"]
    # If cached value is just a hash string, no findings cached yet
    return None


def cache_findings(filepath: str, findings: List[dict], cache: Dict):
    """Store findings for a file in the cache."""
    if "files" not in cache:
        cache["files"] = {}
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        cache["files"][filepath] = {
            "hash": _file_hash(content),
            "findings": findings,
            "scanned_at": __import__("datetime").datetime.now().isoformat(),
        }
        save_cache(cache)
    except Exception as e:
        logger.warning("Failed to cache findings for %s: %s", filepath, e)


def clear_cache():
    """Delete the entire codebase cache."""
    import shutil
    if os.path.exists(CACHE_DIR):
        shutil.rmtree(CACHE_DIR)
    return True


def get_cache_stats() -> Dict:
    """Get statistics about the cache."""
    cache = load_cache()
    files = cache.get("files", {})
    total = len(files)
    with_findings = 0
    for f in files.values():
        if isinstance(f, dict) and f.get("findings"):
            with_findings += 1
    return {
        "total_files": total,
        "files_with_findings": with_findings,
        "last_scan": cache.get("last_scan"),
        "cache_size_bytes": os.path.getsize(CACHE_INDEX) if os.path.exists(CACHE_INDEX) else 0,
    }