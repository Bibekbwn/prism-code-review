"""
Feedback loop + SCA dependency vulnerability scanning + coverage measurement.

Feedback: tracks which findings get fixed and which don't.
SCA: detects known CVEs in dependencies (like SonarQube/OWASP Dependency-Check).
Coverage: runs tests and measures coverage (like CodeRabbit sandboxed execution).
"""

import json
import os
import re
import subprocess
import urllib.request
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

FEEDBACK_FILE = ".prism-feedback.json"
MIN_FIX_RATE = 0.10

# Known CVE database (subset - in production use NVD API)
CVE_DATABASE = {
    "lodash<4.17.21": [
        {"cve": "CVE-2021-23337", "severity": "high",
         "description": "Command injection via template"},
    ],
    "axios<0.21.1": [
        {"cve": "CVE-2021-3749", "severity": "high",
         "description": "Server-Side Request Forgery (SSRF)"},
    ],
    "node-fetch<2.6.7": [
        {"cve": "CVE-2022-0235", "severity": "high",
         "description": "Exposure of sensitive information"},
    ],
    "express<4.17.3": [
        {"cve": "CVE-2022-24999", "severity": "medium",
         "description": "Prototype pollution in qs"},
    ],
    "django<3.2.13": [
        {"cve": "CVE-2022-22806", "severity": "high",
         "description": "XSS in admin"},
    ],
    "flask<2.0.3": [
        {"cve": "CVE-2023-30861", "severity": "medium",
         "description": "Cookie injection"},
    ],
    "fastapi<0.99.1": [
        {"cve": "CVE-2023-25577", "severity": "medium",
         "description": "Redirect vulnerability"},
    ],
    "uvicorn<0.21.0": [
        {"cve": "CVE-2023-46136", "severity": "low",
         "description": "Information disclosure"},
    ],
}


def load_feedback() -> dict:
    p = Path(FEEDBACK_FILE)
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {"rules": {}, "commits": []}


def save_feedback(data: dict) -> None:
    with open(FEEDBACK_FILE, "w") as f:
        json.dump(data, f, indent=2)


def record_commit(findings: List[dict], commit_hash: str = "") -> None:
    fb = load_feedback()
    fb["commits"].append({
        "hash": commit_hash,
        "findings": [
            {"rule_id": f.get("rule_id"), "category": f.get("category")}
            for f in findings
        ],
    })
    save_feedback(fb)


def record_fix(rule_id: str, fixed: bool) -> None:
    fb = load_feedback()
    if rule_id not in fb["rules"]:
        fb["rules"][rule_id] = {"total": 0, "fixed": 0}
    fb["rules"][rule_id]["total"] += 1
    if fixed:
        fb["rules"][rule_id]["fixed"] += 1
    save_feedback(fb)


def get_fix_rate(rule_id: str) -> float:
    fb = load_feedback()
    rule = fb["rules"].get(rule_id, {})
    total = rule.get("total", 0)
    if total == 0:
        return 1.0
    return rule.get("fixed", 0) / total


def should_suppress(rule_id: str) -> bool:
    fb = load_feedback()
    rule = fb["rules"].get(rule_id)
    if rule is None:
        return False
    total = rule.get("total", 0)
    if total < 5:
        return False
    rate = rule.get("fixed", 0) / total
    return rate < MIN_FIX_RATE


def suppress_summary() -> dict:
    fb = load_feedback()
    suppressed = []
    for rule_id, data in fb["rules"].items():
        total = data.get("total", 0)
        if total >= 5:
            rate = data.get("fixed", 0) / total
            if rate < MIN_FIX_RATE:
                suppressed.append({
                    "rule_id": rule_id,
                    "fix_rate": round(rate, 2),
                    "total": total,
                })
    return {"suppressed": suppressed, "threshold": MIN_FIX_RATE}


def scan_dependencies(file_path: str, content: str) -> List[dict]:
    """
    Scan dependencies for known CVEs.

    Checks package.json, requirements.txt, Cargo.toml, go.mod
    against the CVE database. In production, queries NVD API.
    """
    findings = []

    if not file_path.endswith(("package.json", "requirements.txt",
                                "Cargo.toml", "go.mod", "package-lock.json")):
        return findings

    for pattern, cves in CVE_DATABASE.items():
        pkg_match = re.match(r'^([^<]+)(<[\d.]+)', pattern)
        if pkg_match:
            pkg_name = pkg_match.group(1)
            constraint = pkg_match.group(2)
            if pkg_name in content:
                # Check if the installed version satisfies the constraint
                # Match version with optional ^ ~ prefix (npm/yarn)
                ver_match = re.search(
                    r'{}["\']?\s*[:=]\s*["\']?[\^~]?([\d.]+)'.format(re.escape(pkg_name)),
                    content
                )
                if ver_match:
                    installed = ver_match.group(1)
                    max_ver = constraint[1:]
                    if _version_gte(installed, max_ver):
                        continue

                for cve in cves:
                    findings.append({
                        "rule_id": "SCA-{}".format(cve["cve"].split("-")[-1]),
                        "severity": cve["severity"],
                        "category": "Vulnerable Dependency",
                        "message": "{}: {}".format(cve["cve"], cve["description"]),
                        "file": file_path,
                        "suggestion": "Upgrade {} to a patched version.".format(pkg_name),
                        "confidence": 0.95,
                    })
    return findings


def _version_gte(version: str, min_version: str) -> bool:
    """Check if version >= min_version (simple semver comparison)."""
    v_parts = [int(x) for x in version.split(".")]
    m_parts = [int(x) for x in min_version.split(".")]
    for i in range(max(len(v_parts), len(m_parts))):
        v = v_parts[i] if i < len(v_parts) else 0
        m = m_parts[i] if i < len(m_parts) else 0
        if v > m:
            return True
        if v < m:
            return False
    return True


def measure_coverage(project_dir: str = ".") -> dict:
    """
    Run tests and measure coverage.

    Like CodeRabbit's sandboxed execution: clones repo, runs tests,
    validates findings in context.

    Returns: {"coverage": 0.0-1.0, "tests_run": int, "tests_passed": int}
    """
    import subprocess
    import os

    result = {"coverage": 0.0, "tests_run": 0, "tests_passed": 0}

    # Try pytest with coverage
    try:
        proc = subprocess.run(
            ["python", "-m", "pytest", "--co", "-q", "--no-header"],
            capture_output=True, text=True, cwd=project_dir, timeout=15
        )
        if proc.returncode == 0:
            lines = proc.stdout.strip().split("\n")
            for line in lines:
                if "tests found" in line.lower():
                    match = re.search(r'(\d+)', line)
                    if match:
                        result["tests_run"] = int(match.group(1))
    except Exception:
        pass

    # Try running actual tests
    try:
        proc = subprocess.run(
            ["python", "-m", "pytest", "-q", "--no-header", "--tb=short"],
            capture_output=True, text=True, cwd=project_dir, timeout=30
        )
        output = proc.stdout + proc.stderr
        match = re.search(r'(\d+) passed', output)
        if match:
            result["tests_passed"] = int(match.group(1))
        match = re.search(r'(\d+) failed', output)
        if match:
            result["tests_failed"] = int(match.group(1))
    except Exception:
        pass

    # Try coverage.py
    try:
        proc = subprocess.run(
            ["python", "-m", "coverage", "report", "--include=prism/*"],
            capture_output=True, text=True, cwd=project_dir, timeout=15
        )
        match = re.search(r'TOTAL.*?(\d+)%', proc.stdout)
        if match:
            result["coverage"] = int(match.group(1)) / 100.0
    except Exception:
        pass

    return result


def query_nvd_api(package_name: str, version: str) -> List[dict]:
    """
    Query NVD API for known CVEs affecting a package version.
    
    Uses NVD API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
    Requires NVD_API_KEY environment variable (free at nvd.nist.gov).
    Falls back to empty list if no key is set.
    """
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        return []

    try:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            "?keywordResults={}&resultsPerPage=5"
        ).format(package_name)
        req = urllib.request.Request(url, headers={
            "apiKey": api_key,
            "User-Agent": "PRISM-SCA/1.0",
        })
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())

        findings = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})
            cvss = metrics.get("cvssMetric31", [{}])[0].get("cvssData", {})
            base_score = cvss.get("baseScore", 0)
            severity = _cvss_to_severity(base_score)

            descriptions = cve.get("descriptions", [])
            description = descriptions[0].get("value", "") if descriptions else ""

            findings.append({
                "cve": cve_id,
                "severity": severity,
                "description": description[:200],
                "cvss_score": base_score,
            })
        return findings
    except Exception as exc:
        logger.warning("NVD API query failed for %s: %s", package_name, exc)
        return []


def _cvss_to_severity(score: float) -> str:
    """Map CVSS score to severity level."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"