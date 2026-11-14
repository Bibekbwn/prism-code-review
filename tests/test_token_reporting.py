"""Token accounting in reports and the HTML dashboard.

The ledger itself is covered in test_product.py; these tests pin the contract
between the review pipeline, the persisted report and the dashboard:

* a report stores the per-review token snapshot (and the index mirrors it),
* reports written before token tracking read as "unknown", not as zero,
* ``prism stats`` totals tokens across reports,
* the dashboard embeds the data and renders the token chart.
"""

import json
from pathlib import Path

from prism import reports


def _token_usage(total=1200, calls=4, estimated=0, provider="gemini"):
    return {
        "calls": calls,
        "input_tokens": total - 200,
        "output_tokens": 200,
        "total_tokens": total,
        "estimated_calls": estimated,
        "by_provider": {
            provider: {
                "calls": calls,
                "input_tokens": total - 200,
                "output_tokens": 200,
            }
        },
    }


def _save(tmp_path, monkeypatch, token_usage, findings=None):
    monkeypatch.chdir(tmp_path)
    return reports.save_report(
        files_reviewed=["app.py"],
        findings=findings if findings is not None else [],
        risk_score=0.1,
        blocking=0,
        commit_allowed=True,
        commit_hash="abc1234",
        branch="main",
        token_usage=token_usage,
    )


class TestTokenPersistence:
    def test_report_and_index_store_token_usage(self, tmp_path, monkeypatch):
        report_id = _save(tmp_path, monkeypatch, _token_usage())

        saved = json.loads(
            (tmp_path / ".prism-reports" / "{}.json".format(report_id))
            .read_text(encoding="utf-8"))
        assert saved["token_usage"]["total_tokens"] == 1200
        assert saved["token_usage"]["calls"] == 4

        index = json.loads(
            (tmp_path / ".prism-reports" / "index.json").read_text(encoding="utf-8"))
        entry = index["reports"][-1]
        assert entry["token_usage"]["total_tokens"] == 1200

    def test_legacy_report_without_the_field_reads_as_unknown(self, tmp_path,
                                                             monkeypatch):
        monkeypatch.chdir(tmp_path)
        # A report written by an older PRISM: no token_usage key at all.
        (tmp_path / ".prism-reports").mkdir()
        (tmp_path / ".prism-reports" / "legacy.json").write_text(
            json.dumps({
                "id": "legacy",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "commit_hash": "deadbee",
                "branch": "main",
                "files_reviewed": ["old.py"],
                "total_findings": 0,
                "blocking": 0,
                "risk_score": 0.0,
                "commit_allowed": True,
                "findings": [],
            }), encoding="utf-8")
        (tmp_path / ".prism-reports" / "index.json").write_text(
            json.dumps({"reports": [{
                "id": "legacy",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "commit_hash": "deadbee",
                "branch": "main",
                "files_reviewed": ["old.py"],
                "total_findings": 0,
                "blocking": 0,
                "risk_score": 0.0,
                "commit_allowed": True,
            }]}), encoding="utf-8")

        trends = reports.get_findings_history()
        assert trends["total_tokens"] == 0
        assert trends["ai_reviews"] == 0
        # Unknown must not be reported as an AI review that spent nothing.
        assert "Total tokens" not in reports.get_report_summary()


class TestTokenTotals:
    def test_history_sums_tokens_and_counts_ai_reviews(self, tmp_path, monkeypatch):
        _save(tmp_path, monkeypatch, _token_usage(total=1000, calls=3))
        _save(tmp_path, monkeypatch, _token_usage(total=500, calls=1,
                                                  estimated=1))

        trends = reports.get_findings_history()
        assert trends["total_tokens"] == 1500
        assert trends["ai_reviews"] == 2
        assert trends["input_tokens"] == 1100
        assert trends["output_tokens"] == 400
        assert trends["estimated_token_calls"] == 1

    def test_zero_token_review_is_not_counted_as_ai(self, tmp_path, monkeypatch):
        _save(tmp_path, monkeypatch, _token_usage(total=0, calls=0))

        trends = reports.get_findings_history()
        assert trends["total_tokens"] == 0
        assert trends["ai_reviews"] == 0
        assert "Total tokens" not in reports.get_report_summary()

    def test_summary_reports_tokens_and_estimate_warning(self, tmp_path,
                                                         monkeypatch):
        _save(tmp_path, monkeypatch, _token_usage(total=1200, calls=4))
        _save(tmp_path, monkeypatch, _token_usage(total=800, calls=2,
                                                  estimated=2))

        summary = reports.get_report_summary()
        assert "Total tokens: 2,000 (in 1,600 / out 400) across 2 AI review(s)" in summary
        assert "2 call(s) used estimated counts" in summary

    def test_back_to_back_reviews_get_distinct_ids(self, tmp_path, monkeypatch):
        """Two reviews in the same clock tick must not share a report file.

        The ID is a microsecond timestamp and the Windows clock moves in ~15 ms
        steps, so back-to-back saves collided: the second report overwrote the
        first while the index kept both, and the totals then counted one report
        twice. This froze the clock to force the collision.
        """
        import datetime as _dt

        frozen = _dt.datetime(2026, 1, 1, 0, 0, 0, tzinfo=_dt.timezone.utc)
        monkeypatch.setattr(
            reports, "datetime",
            type("_Clock", (), {"now": staticmethod(lambda tz=None: frozen)})())

        first = _save(tmp_path, monkeypatch, _token_usage(total=1200, calls=4))
        second = _save(tmp_path, monkeypatch, _token_usage(total=800, calls=2))

        assert first != second
        assert len(list((tmp_path / ".prism-reports").glob("*.json"))) == 3
        assert reports.get_findings_history()["total_tokens"] == 2000
        assert reports.get_findings_history()["ai_reviews"] == 2


class TestDashboardTokens:
    def test_dashboard_embeds_usage_and_renders_chart(self, tmp_path, monkeypatch):
        _save(tmp_path, monkeypatch, _token_usage(total=1234, calls=3))

        from prism.commands_reports import build_dashboard
        path = build_dashboard(open_browser=False)

        assert path is not None
        html = Path(path).read_text(encoding="utf-8")
        # Data contract: the snapshot is inlined for the page to render.
        assert '"token_usage"' in html
        assert '"total_tokens": 1234' in html
        # Template contract: stat card, per-card label and the chart exist.
        assert "Tokens by Review" in html
        assert "function tokenLabel" in html
        assert "function tokenDetail" in html

    def test_dashboard_handles_reports_without_tokens(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".prism-reports").mkdir()
        (tmp_path / ".prism-reports" / "legacy.json").write_text(
            json.dumps({
                "id": "legacy",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "commit_hash": "deadbee",
                "branch": "main",
                "files_reviewed": ["old.py"],
                "total_findings": 1,
                "blocking": 0,
                "risk_score": 0.0,
                "commit_allowed": True,
                "findings": [{
                    "agent": "security", "severity": "low", "category": "Style",
                    "problem": "old finding", "file": "old.py", "line": 1,
                }],
            }), encoding="utf-8")
        (tmp_path / ".prism-reports" / "index.json").write_text(
            json.dumps({"reports": [{
                "id": "legacy",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "commit_hash": "deadbee",
                "branch": "main",
                "files_reviewed": ["old.py"],
                "total_findings": 1,
                "blocking": 0,
                "risk_score": 0.0,
                "commit_allowed": True,
            }]}), encoding="utf-8")

        from prism.commands_reports import build_dashboard
        path = build_dashboard(open_browser=False)

        html = Path(path).read_text(encoding="utf-8")
        # Missing field is tolerated: the template's three-state label covers it.
        assert "report predates token tracking" in html
        assert "No AI usage recorded" in html