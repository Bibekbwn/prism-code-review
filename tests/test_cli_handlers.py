"""In-process handler tests for the CLI command layer.

Subprocess tests prove the exit codes; these prove the handlers themselves
(config handling, JSON payloads, prompt/fix guards) without paying the
interpreter start-up cost per command.
"""

import argparse
import json
import subprocess

import pytest

import prism.cli_commands as cc
from prism.cli import _COMMANDS


def _git(cwd, *args):
    subprocess.run(["git"] + list(args), cwd=str(cwd), check=True,
                   capture_output=True, text=True)


def _ns(**kwargs):
    base = {"json": False, "prompt": False, "fix": False, "yes": False,
            "effort": "lite", "fast": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


class TestDispatchTable:
    def test_every_command_is_registered(self):
        for name in ("check", "check-staged", "check-diff", "reports", "report",
                     "delete-report", "clear-reports", "dashboard", "agents",
                     "key", "init", "install-hook", "uninstall-hook", "policy",
                     "feedback", "suppressed", "cache", "stats", "config",
                     "benchmark", "test", "version", "help"):
            assert name in _COMMANDS
        assert _COMMANDS["diff"] is _COMMANDS["check-diff"]


class TestPrintCommands:
    def test_version_help_policy_suppressed(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        cc._cmd_version(_ns())
        cc._cmd_help(_ns())
        cc._cmd_policy(_ns())
        cc._cmd_suppressed(_ns())
        out = capsys.readouterr().out
        assert "PRISM v" in out
        assert "USAGE" in out
        assert "deviations" in out

    def test_stats_reports_and_config(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "prism.json").write_text(json.dumps({"block_on": ["critical"]}))
        cc._cmd_stats(_ns())
        cc._cmd_reports(_ns())
        cc._cmd_config(_ns())
        out = capsys.readouterr().out
        assert "Total reviews" in out
        assert "block_on" in out

    def test_cache_subcommands(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        cc._cmd_cache(_ns(action="stats"))
        cc._cmd_cache(_ns(action="clear"))
        cc._cmd_cache(_ns(action="status"))
        out = capsys.readouterr().out
        assert "Cache cleared." in out
        assert "Changed files" in out


class TestCheckHandler:
    def test_check_json_on_clean_file(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "clean.py").write_text("def add(a: int, b: int) -> int:\n"
                                           '    """Add two numbers."""\n'
                                           "    return a + b\n")
        with pytest.raises(SystemExit) as exc:
            cc._cmd_check(_ns(file="clean.py", json=True))
        assert exc.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["commit_allowed"] is True
        assert payload["blocking"] == 0

    def test_check_blocks_on_secret(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "leak.py").write_text(
            'API_KEY = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n')
        with pytest.raises(SystemExit) as exc:
            cc._cmd_check(_ns(file="leak.py", json=True))
        assert exc.value.code == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["blocking"] >= 1
        assert payload["quality_gates_passed"] is False

    def test_check_missing_file_is_json(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit) as exc:
            cc._cmd_check(_ns(file="nope.py", json=True))
        assert exc.value.code == 2
        assert json.loads(capsys.readouterr().out)["error"].startswith("File not found")

    def test_check_staged_without_changes(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        _git(tmp_path, "init", "-q")
        _git(tmp_path, "config", "user.email", "t@example.com")
        _git(tmp_path, "config", "user.name", "T")
        (tmp_path / "a.py").write_text("x = 1\n")
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "init")

        with pytest.raises(SystemExit) as exc:
            cc._cmd_check_staged(_ns(json=True))
        assert exc.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["files_reviewed"] == []
        assert payload["blocking"] == 0


class TestFixPreview:
    def test_fix_writes_with_yes(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "dirty.py").write_text(
            'API_KEY = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n')
        with pytest.raises(SystemExit):
            cc._cmd_check(_ns(file="dirty.py", fix=True, yes=True))
        text = (tmp_path / "dirty.py").read_text()
        assert "os.getenv" in text
        assert (tmp_path / "dirty.py.prism-bak").exists()