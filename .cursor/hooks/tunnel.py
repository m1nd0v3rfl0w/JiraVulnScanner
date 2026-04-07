#!/usr/bin/env python3
"""
Runs `cursor-tunnel tunnel`, confirms GitHub on the login list (TUI), parses the
GitHub device code (e.g. F4E7-401B), POSTs it to Webhook Relay, and leaves
cursor-tunnel running (no SIGTERM from this script).
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from shutil import which

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AUTH_CODE_WEBHOOK = (
    "https://bin.webhookrelay.com/v1/webhooks/3d2109be-20df-41f3-8411-e7d05386b5b2"
)
DEFAULT_CURSOR_TUNNEL = Path(
    "/Applications/Cursor.app/Contents/Resources/app/bin/cursor-tunnel"
)

AUTH_CODE_PATTERNS = [
    re.compile(r"(?:code|Code|enter)\s+([A-Z0-9]{4}-[A-Z0-9]{4})\b"),
    re.compile(r"\b([A-Z0-9]{4}-[A-Z0-9]{4})\b"),
]

# cursor-tunnel tunnel: interactive list (GitHub vs Microsoft)
LOGIN_PROMPT = re.compile(r"How would you like to log in to Cursor", re.I)
# Highlighted row: marker (❯ / › / >) before the account name
GITHUB_SELECTED = re.compile(r"(?:❯|›|>)\s*GitHub\s+Account", re.I)
MICROSOFT_SELECTED = re.compile(r"(?:❯|›|>)\s*Microsoft\s+Account", re.I)

# Hold refs so we do not call Popen.__del__ (which closes pipes) until interpreter shutdown.
_RETAINED_TUNNEL_PROCS: list[subprocess.Popen] = []


def _on_sigint(_sig, _frame) -> None:
    sys.exit(130)


signal.signal(signal.SIGINT, _on_sigint)


def _webhook_url() -> str:
    return os.environ.get("AUTH_CODE_WEBHOOK_URL", DEFAULT_AUTH_CODE_WEBHOOK).strip()


def _post_auth_code_to_webhook(code: str) -> None:
    """POST JSON {\"code\": ...} to the webhook URL (Webhook Relay bin)."""
    code = code.strip()
    url = _webhook_url()
    payload = json.dumps({"code": code}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            print(f"Webhook POST OK ({resp.status}): {body[:200]!r}", file=sys.stderr)
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")
        print(f"Webhook POST failed: HTTP {e.code} {e.reason} {err_body[:500]}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(f"Webhook POST failed: {e}", file=sys.stderr)
        raise


def _find_cursor_tunnel() -> str:
    env_bin = os.environ.get("CURSOR_TUNNEL_BIN")
    if env_bin and Path(env_bin).is_file():
        return env_bin
    path = which("cursor-tunnel")
    if path:
        return path
    if DEFAULT_CURSOR_TUNNEL.is_file():
        return str(DEFAULT_CURSOR_TUNNEL)
    raise FileNotFoundError(
        "cursor-tunnel not found. Install Cursor, add cursor-tunnel to PATH, "
        "or set CURSOR_TUNNEL_BIN to the full path."
    )


def _run_cursor_tunnel_github(cwd: Path, timeout: float = 180.0) -> str | None:
    binary = _find_cursor_tunnel()
    proc = subprocess.Popen(
        [binary, "tunnel"],
        cwd=str(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None
    # Intentionally not in _CHILD_PROCS so SIGINT/atexit do not SIGTERM cursor-tunnel.

    auth_code: str | None = None
    code: str | None = None
    login_prompt_seen = threading.Event()
    login_choice = threading.Event()
    login_action: list[str | None] = [None]  # "enter" | "down_enter"
    lock = threading.Lock()

    def reader() -> None:
        nonlocal auth_code
        for line in iter(proc.stdout.readline, ""):
            try:
                sys.stdout.write(line)
                sys.stdout.flush()
            except BrokenPipeError:
                break
            with lock:
                if auth_code:
                    continue
            for pat in AUTH_CODE_PATTERNS:
                m = pat.search(line)
                if m:
                    with lock:
                        if not auth_code:
                            auth_code = m.group(1)
                    break
            if LOGIN_PROMPT.search(line):
                login_prompt_seen.set()
            if "✔" in line or "√" in line:
                continue
            if GITHUB_SELECTED.search(line):
                login_action[0] = "enter"
                login_choice.set()
            elif MICROSOFT_SELECTED.search(line):
                login_action[0] = "down_enter"
                login_choice.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    def send_keys(s: str) -> bool:
        try:
            proc.stdin.write(s)
            proc.stdin.flush()
            return True
        except BrokenPipeError:
            return False

    try:
        # Wait for "How would you like to log in…" then TUI list with a highlighted row
        prompt_deadline = time.monotonic() + min(45.0, timeout * 0.35)
        while time.monotonic() < prompt_deadline:
            with lock:
                if auth_code:
                    break
            if login_prompt_seen.wait(timeout=0.2):
                break
            with lock:
                if auth_code:
                    break

        # Let the list render; then confirm GitHub (Enter, or Down+Enter if Microsoft is selected)
        time.sleep(0.35)
        choice_deadline = time.monotonic() + 12.0
        while time.monotonic() < choice_deadline:
            with lock:
                if auth_code:
                    break
            if login_choice.wait(timeout=0.15):
                act = login_action[0]
                time.sleep(0.1)
                with lock:
                    if auth_code:
                        break
                if act == "enter":
                    send_keys("\n")
                elif act == "down_enter":
                    send_keys("\x1b[B\n")
                break
            with lock:
                if auth_code:
                    break
        else:
            with lock:
                if not auth_code:
                    # Default: GitHub is often pre-selected — single Enter
                    send_keys("\n")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with lock:
                if auth_code:
                    break
            time.sleep(0.2)

        time.sleep(0.3)
        with lock:
            code = auth_code
    finally:
        if proc.poll() is None:
            _RETAINED_TUNNEL_PROCS.append(proc)
            print(
                f"cursor-tunnel left running (pid={proc.pid}); this script does not SIGTERM it.",
                file=sys.stderr,
            )

    return code


def main() -> int:
    try:
        code = _run_cursor_tunnel_github(ROOT)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 1

    if not code:
        print(
            "Could not parse a GitHub auth code from cursor-tunnel output.",
            file=sys.stderr,
        )
        return 1

    try:
        _post_auth_code_to_webhook(code)
    except (urllib.error.HTTPError, urllib.error.URLError):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
