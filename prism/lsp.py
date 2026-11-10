"""
PRISM Language Server (LSP) — IDE integration.

Implements a minimal Language Server Protocol server over stdio using only
the standard library. No external dependencies. Any editor with LSP support
(VS Code, Vim, Emacs, Zed, Helix) shows PRISM findings inline as you type.

Protocol: JSON-RPC 2.0 over stdio (Content-Length headers).

Supported methods:
  initialize             — server capabilities
  shutdown               — graceful exit
  textDocument/didOpen   — start reviewing a file
  textDocument/didChange — re-review on edit
  textDocument/didClose  — clear diagnostics

Diagnostics are published via textDocument/publishDiagnostics.

Usage:
  python -m prism.lsp

VS Code settings.json (example):
  "languages.python": {
    "uri": "file:///abs/path/to/prism/lsp.py"
  }
"""

import json
import os
import sys
import subprocess
import threading
from pathlib import Path

# Ensure prism package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from prism.cli import review_file, load_config
from prism.agents import Blocker


def _read_message():
    """Read one LSP message from stdin. Returns dict or None on EOF."""
    try:
        headers = {}
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                return None
            line = line.decode("utf-8").rstrip("\r\n")
            if not line:
                break
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        length = int(headers.get("content-length", "0"))
        if length == 0:
            return None
        body = sys.stdin.buffer.read(length)
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def _send_message(msg):
    """Write one LSP message to stdout with Content-Length header."""
    data = json.dumps(msg).encode("utf-8")
    header = "Content-Length: {}\r\n\r\n".format(len(data)).encode("utf-8")
    sys.stdout.buffer.write(header + data)
    sys.stdout.buffer.flush()


def _review_file_to_diagnostics(file_path, config, diff=""):
    """Run PRISM review and convert findings to LSP diagnostics."""
    try:
        results, _score = review_file(file_path, config, "lite", True, diff)
    except Exception as exc:
        return [], str(exc)

    diagnostics = []
    for result in results:
        for f in result.findings:
            sev_map = {
                "critical": 1,  # DiagnosticSeverity.Error
                "high": 1,
                "medium": 2,    # DiagnosticSeverity.Warning
                "low": 3,       # DiagnosticSeverity.Information
                "info": 4,      # DiagnosticSeverity.Hint
            }
            diagnostics.append({
                "range": {
                    "start": {"line": max(0, (f.line or 1) - 1), "character": 0},
                    "end": {"line": max(0, (f.line or 1) - 1), "character": 80},
                },
                "severity": sev_map.get(f.severity.value, 2),
                "source": "prism",
                "code": f.rule_id,
                "message": "[{}] {}: {}".format(
                    f.agent, f.category, f.message
                ),
                "data": {
                    "suggestion": f.suggestion,
                    "suggested_code": f.suggested_code,
                },
            })
    return diagnostics, None


def _publish_diagnostics(uri, diagnostics):
    """Send textDocument/publishDiagnostics notification."""
    _send_message({
        "jsonrpc": "2.0",
        "method": "textDocument/publishDiagnostics",
        "params": {
            "uri": uri,
            "diagnostics": diagnostics,
        },
    })


def run():
    """Main LSP server loop."""
    # Read initialize request
    init = _read_message()
    if init is None:
        return

    # Send initialized response
    _send_message({
        "jsonrpc": "2.0",
        "id": init.get("id"),
        "result": {
            "capabilities": {
                "textDocumentSync": 1,  # Full sync
            },
        },
    })

    config = load_config()
    open_files = {}  # uri -> file_path

    while True:
        msg = _read_message()
        if msg is None:
            break

        method = msg.get("method")
        params = msg.get("params", {})

        if method == "textDocument/didOpen":
            uri = params["textDocument"]["uri"]
            file_path = uri.replace("file://", "")
            # Handle Windows paths: file:///C:/... -> C:/...
            if file_path.startswith("/") and len(file_path) > 2 and file_path[2] == ":":
                file_path = file_path[1:]
            open_files[uri] = file_path

            # Review in a thread so we don't block the LSP loop
            def _review(uri=uri, file_path=file_path):
                diag, _err = _review_file_to_diagnostics(file_path, config)
                _publish_diagnostics(uri, diag)

            threading.Thread(target=_review, daemon=True).start()

        elif method == "textDocument/didChange":
            uri = params["textDocument"]["uri"]
            if uri in open_files:
                diag, _err = _review_file_to_diagnostics(open_files[uri], config)
                _publish_diagnostics(uri, diag)

        elif method == "textDocument/didClose":
            uri = params["textDocument"]["uri"]
            open_files.pop(uri, None)
            _publish_diagnostics(uri, [])  # Clear diagnostics

        elif method == "shutdown":
            _send_message({"jsonrpc": "2.0", "id": msg.get("id"), "result": None})
            break

        elif method == "exit":
            break

        # Notifications without ID don't get a response


if __name__ == "__main__":
    run()