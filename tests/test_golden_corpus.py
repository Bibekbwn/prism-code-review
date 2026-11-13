"""Golden-corpus tests: lock auto-fix and dedup behaviour with data files.

Add a case to tests/fixtures/autofix_cases.json or dedup_cases.json instead of
writing another test function. Precision/recall of both heuristics can then be
measured by counting `collapse: true` vs `false` in the dedup corpus.
"""

import json
from pathlib import Path

import pytest

from prism.agents import Finding, Severity
from prism.autofix import apply_fixes, generate_fix
from prism.cli_review import _same_issue

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(**kwargs):
    return Finding(
        agent=kwargs.pop("agent", "security"),
        severity=kwargs.pop("severity", Severity.HIGH),
        category=kwargs.pop("category", "Secret Exposure"),
        message=kwargs.pop("message", ""),
        file=kwargs.pop("file", "x.py"),
        line=kwargs.pop("line", 1),
        rule_id=kwargs.pop("rule_id", ""),
        confidence=kwargs.pop("confidence", 0.85),
    )


class TestAutoFixCorpus:
    @pytest.mark.parametrize("case", json.loads(
        (FIXTURES / "autofix_cases.json").read_text(encoding="utf-8")),
        ids=lambda c: c["name"])
    def test_case(self, case):
        finding = _finding(line=case["line"], rule_id=case["rule_id"],
                           category=case["category"], message=case["message"])
        fixed_line = generate_fix(finding, case["source"])

        if case["expected"] is None:
            assert fixed_line is None
            return

        assert fixed_line == case["expected"].rstrip("\n")
        # The generated line must keep the file parseable when applied.
        lines = case["source"].split("\n")
        lines[case["line"] - 1] = fixed_line
        compile(apply_fixes([(finding, fixed_line)], case["source"]),
                "x.py", "exec")

    def test_corpus_is_not_empty(self):
        cases = json.loads((FIXTURES / "autofix_cases.json").read_text(encoding="utf-8"))
        assert len(cases) >= 6
        assert any(c["expected"] is None for c in cases)


class TestDedupCorpus:
    @pytest.mark.parametrize("case", json.loads(
        (FIXTURES / "dedup_cases.json").read_text(encoding="utf-8")),
        ids=lambda c: c["name"])
    def test_case(self, case):
        a = _finding(category=case["a"]["category"], message=case["a"]["message"])
        b = _finding(category=case["b"]["category"], message=case["b"]["message"])
        assert _same_issue(a, b) is case["collapse"]

    def test_precision_and_recall_are_reported(self):
        cases = json.loads((FIXTURES / "dedup_cases.json").read_text(encoding="utf-8"))
        positives = [c for c in cases if c["collapse"]]
        negatives = [c for c in cases if not c["collapse"]]
        assert positives and negatives

        tp = sum(1 for c in positives
                 if _same_issue(_finding(**c["a"]), _finding(**c["b"])))
        tn = sum(1 for c in negatives
                 if not _same_issue(_finding(**c["a"]), _finding(**c["b"])))
        assert tp == len(positives)
        assert tn == len(negatives)