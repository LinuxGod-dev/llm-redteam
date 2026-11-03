"""Integration test of HttpTarget + CLI against a local OpenAI-compatible server.

The server reuses MockTarget's logic and puts a naive 403 guard in front of it,
so this validates the HTTP path (request shape, tool_calls parsing, block
detection, scope guard, config loading). It is NOT a real-model result.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import yaml

from llmredteam.cli import main
from llmredteam.targets import MockTarget

_BACKEND = MockTarget()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        user = [m for m in body["messages"] if m["role"] == "user"][-1]["content"]
        if "ignore previous instructions" in user.lower():
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"error":"blocked by guard"}')
            return
        r = _BACKEND.send(user)
        msg = {"role": "assistant", "content": r.text}
        if r.tool_calls and "tools" in body:
            msg["tool_calls"] = [{"id": "c1", "type": "function", "function": {
                "name": c["name"], "arguments": json.dumps(c["args"])}} for c in r.tool_calls]
        out = json.dumps({"choices": [{"message": msg}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture()
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


def test_cli_against_http_target(server, tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({
        "target": {"base_url": server, "model": "test", "tools": True},
        "run": {"mutators": ["none", "base64"], "delay_seconds": 0}}))
    out = tmp_path / "out"
    rc = main(["run", "--target", "http", "--config", str(cfg), "--out", str(out)])
    assert rc == 0
    data = json.loads((out / "results.json").read_text())
    statuses = {r["status"] for r in data["results"]}
    assert "blocked" in statuses      # guard returned 403 on plain override
    assert "success" in statuses      # encoded / tool attacks got through
    assert "error" not in statuses
    tool_hits = [r for r in data["results"] if r["attack_id"].startswith("ea-") and r["status"] == "success"]
    assert tool_hits                  # OpenAI-style tool_calls parsed correctly


def test_cli_refuses_out_of_scope_host(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({"target": {"base_url": "https://api.example-llm.com/v1", "model": "x"}}))
    assert main(["run", "--target", "http", "--config", str(cfg), "--out", str(tmp_path / "o")]) == 2


def test_fail_on_asr_gate(server, tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({"target": {"base_url": server, "model": "t", "tools": True},
                                   "run": {"mutators": ["none"]}}))
    assert main(["run", "--target", "http", "--config", str(cfg), "--out", str(tmp_path / "o"),
                 "--fail-on-asr", "5"]) == 1
