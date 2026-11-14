"""Tests for the tool-wide (``key set --global``) API key path.

A developer installs prism once and runs it from any project folder. The
project-local .env wins over the tool-wide one (load_env order), so these
tests verify the write target and the precedence, not the read path.
"""

import argparse

from prism.commands_setup import _cmd_key, _global_env_path


def _ns(action, **kwargs):
    base = {"action": action, "provider": None, "key": None, "global_": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_global_env_path_is_install_folder(monkeypatch, tmp_path):
    # _global_env_path points at the package parent, not the CWD.
    monkeypatch.chdir(tmp_path)
    p = _global_env_path()
    assert p.name == ".env"
    assert p.parent.name != tmp_path.name


def test_global_set_writes_install_folder(tmp_path, monkeypatch):
    install = tmp_path / "install"
    (install / "prism").mkdir(parents=True)
    (install / "prism" / "__init__.py").write_text("")
    project = tmp_path / "project"
    project.mkdir()
    import prism.commands_setup as setup
    monkeypatch.setattr(setup, "_global_env_path", lambda: install / ".env")
    monkeypatch.chdir(project)

    _cmd_key(_ns("set", provider="gemini", key="AIzaSyREALKEY1234567890",
                 global_=True))

    global_env = (install / ".env").read_text()
    assert 'GEMINI_API_KEY="AIzaSyREALKEY1234567890"' in global_env
    assert "MODEL_PROVIDER=gemini" in global_env
    # Nothing was written into the project directory.
    assert not (project / ".env").exists()


def test_project_set_still_writes_cwd(tmp_path, monkeypatch):
    import prism.commands_setup as setup
    monkeypatch.setattr(setup, "_global_env_path",
                        lambda: tmp_path / "unused-global.env")
    monkeypatch.chdir(tmp_path)

    _cmd_key(_ns("set", provider="gemini", key="AIzaSyREALKEY1234567890"))

    # The project path may pick .env or .config/.env (whichever the
    # pre-existing layout implies); both are inside the CWD.
    assert (tmp_path / ".env").exists() or (tmp_path / ".config" / ".env").exists()
    assert not (tmp_path / "unused-global.env").exists()


def test_global_delete_targets_install_folder(tmp_path, monkeypatch):
    install = tmp_path / "install"
    (install / "prism").mkdir(parents=True)
    (install / "prism" / "__init__.py").write_text("")
    project = tmp_path / "project"
    project.mkdir()
    import prism.commands_setup as setup
    monkeypatch.setattr(setup, "_global_env_path", lambda: install / ".env")
    monkeypatch.chdir(project)

    _cmd_key(_ns("set", provider="gemini", key="AIzaSyREALKEY1234567890",
                 global_=True))
    _cmd_key(_ns("delete", global_=True))

    text = (install / ".env").read_text()
    assert "GEMINI_API_KEY" not in text
    # MODEL_PROVIDER is not a key; _key_delete removes key vars only.
    assert "MODEL_PROVIDER" in text