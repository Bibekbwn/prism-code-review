"""
Local report storage for PRISM findings.

Saves every review result to .prism-reports/ so developers can:
- View history of all reviews
- See what was fixed and what remains
- Track risk score over time
- Review past findings without re-running

No server, no database, no cloud — just local JSON files.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

REPORTS_DIR = ".prism-reports"
REPORT_INDEX = os.path.join(REPORTS_DIR, "index.json")


def _ensure_dir():
    Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)


def save_report(
    files_reviewed: List[str],
    findings: List[dict],
    risk_score: float,
    blocking: int,
    commit_allowed: bool,
    commit_hash: str = "",
    branch: str = "",
    token_usage: Optional[dict] = None,
) -> str:
    """Save a review report to .prism-reports/ and return the report ID.

    ``token_usage`` is the per-review ledger snapshot from
    :func:`prism.token_usage.summary`. Reports written before token tracking
    existed simply lack the field; readers must treat "absent" as unknown, not
    as zero, or cost trends get a fake dip.
    """
    _ensure_dir()

    report_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    report = {
        "id": report_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit_hash": commit_hash,
        "branch": branch,
        "files_reviewed": files_reviewed,
        "total_findings": len(findings),
        "blocking": blocking,
        "risk_score": risk_score,
        "commit_allowed": commit_allowed,
        "token_usage": token_usage,
        "findings": findings,
    }

    # Save individual report
    report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    # Update index
    _update_index(report_id, report)

    return report_id


def _update_index(report_id: str, report: dict):
    """Add or update entry in the index file."""
    index = load_index()
    index["reports"].append({
        "id": report_id,
        "timestamp": report["timestamp"],
        "commit_hash": report["commit_hash"],
        "branch": report["branch"],
        "files_reviewed": report["files_reviewed"],
        "total_findings": report["total_findings"],
        "blocking": report["blocking"],
        "risk_score": report["risk_score"],
        "commit_allowed": report["commit_allowed"],
        "token_usage": report.get("token_usage"),
    })
    # Keep last 500 entries
    if len(index["reports"]) > 500:
        index["reports"] = index["reports"][-500:]

    with open(REPORT_INDEX, "w") as f:
        json.dump(index, f, indent=2)


def load_index() -> dict:
    """Load the report index."""
    if os.path.exists(REPORT_INDEX):
        with open(REPORT_INDEX) as f:
            return json.load(f)
    return {"reports": []}


def load_report(report_id: str) -> Optional[dict]:
    """Load a specific report by ID."""
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def get_recent_reports(limit: int = 20) -> List[dict]:
    """Get the most recent reports."""
    index = load_index()
    return index["reports"][-limit:]


def get_findings_history() -> dict:
    """Get a summary of findings over time for trend analysis."""
    index = load_index()
    trends = {
        "total_reviews": len(index["reports"]),
        "total_findings": 0,
        "total_blocking": 0,
        "commits_blocked": 0,
        "risk_scores": [],
        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings_by_agent": {},
        "findings_by_rule": {},
        # Token accounting. ``ai_reviews`` counts only reports that actually
        # spent tokens, so a repo that never configured a key shows 0 rather
        # than "one review with zero tokens".
        "total_tokens": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "ai_reviews": 0,
        "estimated_token_calls": 0,
    }

    for r in index["reports"]:
        trends["total_findings"] += r["total_findings"]
        trends["total_blocking"] += r["blocking"]
        if not r["commit_allowed"]:
            trends["commits_blocked"] += 1
        trends["risk_scores"].append({
            "timestamp": r["timestamp"],
            "risk_score": r["risk_score"],
        })

    # Scan individual reports for detailed stats
    for r in index["reports"]:
        report = load_report(r["id"])
        if report:
            token_usage = report.get("token_usage")
            if token_usage:
                trends["total_tokens"] += token_usage.get("total_tokens", 0)
                trends["input_tokens"] += token_usage.get("input_tokens", 0)
                trends["output_tokens"] += token_usage.get("output_tokens", 0)
                trends["estimated_token_calls"] += token_usage.get(
                    "estimated_calls", 0)
                if token_usage.get("calls"):
                    trends["ai_reviews"] += 1
            for f in report.get("findings", []):
                sev = f.get("severity", "unknown")
                agent = f.get("agent", "unknown")
                rule = f.get("rule_id", "unknown")
                trends["findings_by_severity"][sev] = \
                    trends["findings_by_severity"].get(sev, 0) + 1
                trends["findings_by_agent"][agent] = \
                    trends["findings_by_agent"].get(agent, 0) + 1
                if rule:
                    trends["findings_by_rule"][rule] = \
                        trends["findings_by_rule"].get(rule, 0) + 1

    return trends


def delete_report(report_id: str) -> bool:
    """Delete a specific report by ID. Returns True if deleted, False if not found."""
    report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if os.path.exists(report_path):
        os.remove(report_path)
        # Update index
        index = load_index()
        index["reports"] = [r for r in index["reports"] if r["id"] != report_id]
        with open(REPORT_INDEX, "w") as f:
            json.dump(index, f, indent=2)
        return True
    return False


def clear_reports() -> int:
    """Delete all report files. Returns the number of reports deleted.

    Deletes files individually rather than rmtree-ing the directory, because
    on Windows the directory itself can be locked (e.g. open in Explorer or
    a file handle held by the dashboard), causing PermissionError.
    """
    if not os.path.exists(REPORTS_DIR):
        return 0
    count = 0
    for name in os.listdir(REPORTS_DIR):
        if not name.endswith(".json"):
            continue
        # index.json is bookkeeping, not a report: deleting it is fine, but it
        # must not inflate the "Deleted N report(s)" count.
        is_index = name == "index.json"
        path = os.path.join(REPORTS_DIR, name)
        try:
            os.remove(path)
            if not is_index:
                count += 1
        except OSError:
            pass
    return count


def get_report_summary() -> str:
    """Get a human-readable summary of all reports."""
    trends = get_findings_history()
    lines = [
        "PRISM Report Summary",
        "====================",
        f"Total reviews: {trends['total_reviews']}",
        f"Total findings: {trends['total_findings']}",
        f"Commits blocked: {trends['commits_blocked']}",
    ]

    if trends["total_tokens"]:
        lines.append(
            f"Total tokens: {trends['total_tokens']:,} "
            f"(in {trends['input_tokens']:,} / out {trends['output_tokens']:,}) "
            f"across {trends['ai_reviews']} AI review(s)")
        if trends["estimated_token_calls"]:
            lines.append(
                f"  {trends['estimated_token_calls']} call(s) used estimated "
                f"counts (provider reported no usage)")

    lines.extend([
        "",
        "By Severity:",
    ])
    for sev, count in trends["findings_by_severity"].items():
        lines.append(f"  {sev}: {count}")

    lines.append("")
    lines.append("By Agent:")
    for agent, count in trends["findings_by_agent"].items():
        lines.append(f"  {agent}: {count}")

    if trends["findings_by_rule"]:
        lines.append("")
        lines.append("Top Rules:")
        for rule, count in sorted(
            trends["findings_by_rule"].items(),
            key=lambda x: x[1], reverse=True
        )[:10]:
            lines.append(f"  {rule}: {count}")

    return "\n".join(lines)