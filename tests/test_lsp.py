"""Test the PRISM LSP server end-to-end.

Simulates an LSP editor: sends initialize, didOpen, didClose, shutdown.
Verifies the server responds with correct capabilities and diagnostics.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

PRISM_DIR = str(Path(__file__).parent.parent)
LSP_SCRIPT = os.path.join(PRISM_DIR, "prism", "lsp.py")


def _send(proc, msg):
    data = json.dumps(msg).encode()
    header = "Content-Length: {}\r\n\r\n".format(len(data)).encode()
    proc.stdin.write(header + data)
    proc.stdin.flush()


def _read_response(proc, timeout=15):
    """Read one LSP message from the server."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Read headers
        headers = {}
        while True:
            line = proc.stdout.readline()
            if not line:
                return None
            line = line.decode().rstrip("\r\n")
            if not line:
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0"))
        if length == 0:
            continue
        body = proc.stdout.read(length)
        return json.loads(body.decode())
    return None


def test_lsp_initialize():
    """LSP server must respond to initialize with capabilities."""
    proc = subprocess.Popen(
        [sys.executable, LSP_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _send(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": os.getpid(),
                "rootUri": "file://" + PRISM_DIR,
                "capabilities": {},
            },
        })
        resp = _read_response(proc)
        assert resp is not None, "no initialize response"
        assert resp.get("id") == 1
        assert "result" in resp
        assert "capabilities" in resp["result"]
        assert "textDocumentSync" in resp["result"]["capabilities"]
    finally:
        _send(proc, {"jsonrpc": "2.0", "method": "exit"})
        proc.wait(timeout=5)


def test_lsp_didopen_returns_diagnostics():
    """didOpen must publish diagnostics for a file with findings."""
    # Use a file with a real secret so the regex agent flags it
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, dir=PRISM_DIR
    ) as f:
        f.write('API_KEY = "supersecretvalue123"\n')
        tmp_path = f.name

    uri = "file://" + os.path.join(PRISM_DIR, tmp_path)
    proc = subprocess.Popen(
        [sys.executable, LSP_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # Initialize
        _send(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"processId": os.getpid(), "rootUri": "file://" + PRISM_DIR,
                       "capabilities": {}},
        })
        _read_response(proc)

        # didOpen
        _send(proc, {
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": "python",
                    "version": 1,
                    "content": 'API_KEY = "supersecretvalue123"\n',
                }
            },
        })

        # Expect publishDiagnostics notification
        resp = _read_response(proc, timeout=30)
        assert resp is not None, "no diagnostics published"
        assert resp.get("method") == "textDocument/publishDiagnostics"
        diags = resp["params"]["diagnostics"]
        assert len(diags) > 0, "expected at least one diagnostic"
        # At least one diagnostic should reference a secret
        messages = " ".join(d["message"] for d in diags).lower()
        assert "secret" in messages or "api" in messages, \
            "expected a secret-related diagnostic, got: " + messages
    finally:
        _send(proc, {"jsonrpc": "2.0", "method": "exit"})
        proc.wait(timeout=5)
        os.unlink(tmp_path)


def test_lsp_didclose_clears_diagnostics():
    """didClose must publish an empty diagnostics array."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, dir=PRISM_DIR
    ) as f:
        f.write("x = 1\n")
        tmp_path = f.name

    uri = "file://" + os.path.join(PRISM_DIR, tmp_path)
    proc = subprocess.Popen(
        [sys.executable, LSP_SCRIPT],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _send(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"processId": os.getpid(), "rootUri": "file://" + PRISM_DIR,
                       "capabilities": {}},
        })
        _read_response(proc)

        _send(proc, {
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": uri, "languageId": "python",
                                        "version": 1, "content": "x = 1\n"}},
        })
        _read_response(proc, timeout=30)  # consume didOpen diagnostics

        _send(proc, {
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": uri}},
        })
        resp = _read_response(proc, timeout=15)
        assert resp is not None
        assert resp.get("method") == "textDocument/publishDiagnostics"
        assert resp["params"]["diagnostics"] == []
    finally:
        _send(proc, {"jsonrpc": "2.0", "method": "exit"})
        proc.wait(timeout=5)
        os.unlink(tmp_path)