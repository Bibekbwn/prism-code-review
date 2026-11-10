import json
import subprocess
from pathlib import Path

DEFAULT_AGENTS = ["security", "quality", "policy", "test",
                  "ai_security", "ai_quality", "ai_policy", "ai_test",
                  "ai_architecture", "ai_performance"]
CONFIDENCE_THRESHOLD = 0.7


def load_config():
    """Load prism.json or .prism.json, falling back to defaults."""
    for name in ["prism.json", ".prism.json"]:
        p = Path(name)
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {
        "agents": DEFAULT_AGENTS,
        "block_on": ["critical", "high"],
        "quality_gates": {
            "max_complexity": 10,
            "max_file_length": 500,
            "min_coverage": 0,
        },
        "confidence_threshold": CONFIDENCE_THRESHOLD,
    }


def load_deviation_policy():
    """Load .prism-policy.json or prism-policy.json, falling back to empty."""
    for name in [".prism-policy.json", "prism-policy.json"]:
        p = Path(name)
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {"deviations": []}


def get_staged_files():
    """Return the list of files staged for commit (git diff --cached)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True,
    )
    return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]


def run_changed_tests(changed_files, timeout=120):
    """Run pytest on changed Python files.

    Returns a dict with test execution results:
      - ok: bool - did tests pass
      - passed: int - tests passed
      - failed: int - tests failed
      - files: list of changed .py files tested
      - output: str - pytest output (last 2000 chars)
      - error: str - if pytest itself crashed

    This closes the "test execution" gap - CodeRabbit runs tests and reports
    real failures. We run only on changed files (fast-path) so it's cheap
    enough for a pre-commit hook.
    """
    import re
    py_files = [f for f in changed_files if f.endswith(".py")]
    if not py_files:
        return {"ok": True, "passed": 0, "failed": 0, "files": [],
                "output": "No Python files changed", "error": None}

    try:
        result = subprocess.run(
            ["python", "-m", "pytest"] + py_files + ["-q", "--no-header"],
            capture_output=True, text=True, timeout=timeout,
        )
        output = (result.stdout + result.stderr)[-2000:]
        passed, failed = 0, 0
        m_pass = re.search(r"(\d+)\s+passed", output)
        m_fail = re.search(r"(\d+)\s+failed", output)
        if m_pass:
            passed = int(m_pass.group(1))
        if m_fail:
            failed = int(m_fail.group(1))

        return {
            "ok": result.returncode == 0,
            "passed": passed,
            "failed": failed,
            "files": py_files,
            "output": output,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False, "passed": 0, "failed": 0, "files": py_files,
            "output": "pytest timed out after {}s".format(timeout),
            "error": "timeout",
        }
    except Exception as exc:
        return {
            "ok": False, "passed": 0, "failed": 0, "files": py_files,
            "output": str(exc),
            "error": str(exc),
        }


def get_file_diff(file_path, context_lines=3):
    """Get the git diff for a file (staged + unstaged changes)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--unified={}".format(context_lines),
             "--", file_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except Exception:
        pass
    return ""


def is_deviation(finding, policy):
    """Return True if the finding matches a configured deviation."""
    for dev in policy.get("deviations", []):
        if (dev.get("rule_id") == finding.rule_id
                and dev.get("file", finding.file) == finding.file):
            return True
    return False
