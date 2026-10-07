#!/usr/bin/env python3
"""Exercise the built executable in a temporary directory with no credentials or CLIs."""

import argparse
from contextlib import contextmanager
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import URLError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    source = (args.source or Path(__file__).resolve().parents[2]).resolve()
    check(binary.is_file(), f"Build Saga first: {binary} does not exist")

    with tempfile.TemporaryDirectory(prefix="saga-smoke-") as directory:
        root = Path(directory)
        shutil.copyfile(source / "saga.json", root / "saga.json")
        # No inherited provider keys, host logins, proxies, or real CLI executables.
        empty_bin = root / "empty-bin"
        empty_bin.mkdir()
        child_env = {"PATH": str(empty_bin)}

        def run(*argv, stdin=""):
            return subprocess.run(
                [str(binary), *argv], cwd=root, env=child_env, input=stdin,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
            )

        @contextmanager
        def serve(*argv):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            base = f"http://127.0.0.1:{port}"
            client = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))

            def request(path, body=None):
                data = json.dumps(body).encode() if body is not None else None
                headers = {"Content-Type": "application/json"} if data else {}
                with client.open(Request(base + path, data=data, headers=headers), timeout=10) as response:
                    check(response.status == 200, f"{path}: HTTP {response.status}")
                    return response.read()

            with tempfile.TemporaryFile(mode="w+") as log:
                process = subprocess.Popen(
                    [str(binary), "serve", "--no-memory", "--port", str(port), *argv],
                    cwd=root, env=child_env, stdout=log, stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        check(process.poll() is None, "Saga exited before accepting requests")
                        try:
                            request("/api/state")
                            break
                        except (URLError, TimeoutError):
                            check(time.monotonic() < deadline, "Saga did not become ready")
                            time.sleep(0.1)
                    yield port, request
                except Exception:
                    log.seek(0)
                    print(log.read(), flush=True)
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

        result = run("help")
        check(result.returncode == 0 and result.stdout.startswith("saga — multi-agent harness"), result.stdout)
        for command in ("doctor", "serve"):
            result = run(command)
            check(result.returncode == 1 and "MEMWAL_PRIVATE_KEY and MEMWAL_ACCOUNT_ID must be set" in result.stdout,
                  f"{command} should explain missing memory keys: {result.stdout}")
        print("PASS help and missing-memory-key diagnostics", flush=True)

        with serve() as (port, request):
            for path in ("/", "/app", "/privacy"):
                check(b"<html" in request(path).lower(), f"{path}: missing HTML")
            for path, file in (
                ("/llms.txt", "llms.txt"), ("/brand.js", "src/web/static/brand.js"),
                ("/mascot.js", "src/web/static/mascot.js"), ("/saga-logo.png", "src/web/static/saga-logo.png"),
            ):
                check(request(path) == (source / file).read_bytes(), f"{path}: embedded asset differs from source; rebuild")
            check(json.loads(request("/api/login", {"handle": "judge-smoke"}))["uid"] == "judge-smoke",
                  "Guest login failed")
            state = json.loads(request("/api/state"))
            check(state["uid"] == "judge-smoke" and not state["memory_enabled"] and state["accounts"] == "host",
                  f"Unexpected guest state: {state}")
            check(json.loads(request("/api/memory/stats")) == {"blobs": 0, "bytes": 0}, "Memory should be off")
            roster = {agent["name"]: agent for agent in state["agents"]}
            check(roster.get("saga", {}).get("primary") is True
                  and roster["saga"]["unavailable"] == "BOUNDLESS_API_KEY not set",
                  "Smoke checks require the stock saga.json with an unconfigured @saga; refusing a real provider call")
            for name in ("claude", "codex", "grok"):
                check(roster[name]["unavailable"] == f"{name} not found on PATH", f"Unexpected status for {name}")
            print("PASS embedded pages, assets, llms.txt, guest login and memory-off state", flush=True)

            for message in ("hello", "@claude hello"):
                events = [json.loads(line) for line in request("/api/chat", {"message": message, "session": "delete-smoke"}).splitlines()]
                failures = [event for event in events if event["type"] == "step_done" and not event["ok"]]
                check(failures and failures[-1]["error"] == "BOUNDLESS_API_KEY not set", f"Unexpected events: {events}")
                check(events[-1]["type"] == "done", "The failed turn did not finish")
                if message.startswith("@claude"):
                    check(any(event["type"] == "fallback" and event["reason"] == "claude not found on PATH"
                              for event in events), "Missing CLI did not produce a visible fallback")
            result = run("serve", "--no-memory", "--port", str(port))
            check(result.returncode == 1 and "cannot listen" in result.stdout, f"Missing occupied-port error: {result.stdout}")
            check(json.loads(request("/api/state"))["uid"] == "judge-smoke", "Server stopped after a failed turn")
            print("PASS missing-provider errors, CLI fallback, occupied port and server recovery", flush=True)

            check(json.loads(request("/api/chats/delete-smoke/delete", {})).get("ok"), "Chat deletion failed")
            check(json.loads(request("/api/chats/delete-smoke")).get("deleted"), "Deleted chat can still be opened")
            events = [json.loads(line) for line in request("/api/chat", {"message": "Reopen", "session": "delete-smoke"}).splitlines()]
            check(any(event["type"] == "error" and "deleted" in event.get("text", "") for event in events),
                  f"Deleted chat accepted a new turn: {events}")
            request("/api/login", {"handle": "other-judge"})
            check(not json.loads(request("/api/chats/delete-smoke")).get("deleted"), "Deletion affected another user")
            print("PASS chat deletion API, blocked reopening and user isolation", flush=True)

        (root / ".env").write_text("MEMWAL_PRIVATE_KEY=\nMEMWAL_ACCOUNT_ID=\nBOUNDLESS_API_KEY=\n")
        result = run("chat", "--user", "judge-smoke", "--no-memory", stdin="hello\n/quit\n")
        check(result.returncode == 0 and "memory off" in result.stdout and "BOUNDLESS_API_KEY not set" in result.stdout,
              f"Terminal chat failed with empty .env values: {result.stdout}")
        print("PASS terminal chat and /quit with empty .env", flush=True)

        # Test a successful streamed turn locally; this is a fixture, not a real model call.
        requests = []

        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for piece in ("SAGA_SMOKE_", "OK"):
                    event = {"choices": [{"delta": {"content": piece}}]}
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")

            def log_message(self, *_):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Provider) as provider:
            worker = threading.Thread(target=provider.serve_forever, daemon=True)
            worker.start()
            try:
                config = {"primary": "fixture", "agents": [{
                    "name": "fixture", "kind": "openai", "model": "fixture",
                    "base_url": f"http://127.0.0.1:{provider.server_port}/v1",
                }]}
                (root / "fixture.json").write_text(json.dumps(config))
                with serve("--config", "fixture.json") as (_, request):
                    request("/api/login", {"handle": "judge-smoke"})
                    check(json.loads(request("/api/chats/delete-smoke")).get("deleted"), "Deletion was lost after restart")
                    events = [json.loads(line) for line in request("/api/chat", {"message": "Reply OK"}).splitlines()]
                    check(any(event["type"] == "step_done" and event["ok"] for event in events), f"No successful step: {events}")
                    check(events[-1]["type"] == "done" and events[-1]["final"] == "SAGA_SMOKE_OK", f"Bad response: {events}")
                    check(len(requests) == 1 and requests[0][0] == "/v1/chat/completions" and requests[0][1]["stream"],
                          f"Unexpected provider request: {requests}")
                    state = json.loads(request("/api/state"))
                    check(not state["memory_enabled"] and not state["recent_writes"], "Memory-off turn queued writes")
            finally:
                provider.shutdown()
                worker.join(timeout=5)
        print("PASS successful streamed chat with a local provider fixture (no real model or Walrus calls)", flush=True)

    print("Local smoke checks passed; temporary servers and files cleaned up.")


if __name__ == "__main__":
    main()
