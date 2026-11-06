"""Synthetic loopback bodies and owned fake processes; no external services."""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from test_runner import FakeApi, _runner_settings

from opsgate import runner


@pytest.mark.parametrize("status", [200, 503])
@pytest.mark.parametrize("size_delta", [0, 1])
def test_api_response_byte_cap(tmp_path: Path, status: int, size_delta: int) -> None:
    # A valid object exactly at the cap must still decode, including a large
    # ticket/context field. No Content-Length: the cap cannot trust headers.
    body = b'{"context":"' + b'x' * (runner.API_RESPONSE_MAX_BYTES - 14 + size_delta) + b'"}'
    assert len(body) == runner.API_RESPONSE_MAX_BYTES + size_delta
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    closed = threading.Event()

    def serve() -> None:
        with listener, listener.accept()[0] as peer:
            peer.settimeout(5)
            peer.recv(65536)
            peer.sendall(f"HTTP/1.1 {status} Test\r\nTransfer-Encoding: chunked\r\n\r\n".encode())
            try:
                for offset in range(0, len(body), 65536):
                    chunk = body[offset:offset + 65536]
                    peer.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                if size_delta:
                    # Leave the body open: rejection must precede EOF.
                    assert peer.recv(1) == b""
                    closed.set()
                else:
                    peer.sendall(b"0\r\n\r\n")
            except (ConnectionError, OSError):
                closed.set()

    settings = replace(_runner_settings(tmp_path), runner_api_base_url=f"http://127.0.0.1:{listener.getsockname()[1]}")
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = runner.RunnerApiClient(settings)
    started = time.monotonic()
    if size_delta or status != 200:
        with pytest.raises(runner.RunnerApiError) as caught:
            client.get_ticket("synthetic")
        assert caught.value.error_code == ("transport_error" if size_delta else "http_error")
        assert "xxx" not in str(caught.value)
        assert settings.runner_token not in str(caught.value)
    else:
        assert len(client.get_ticket("synthetic")["context"]) == len(body) - 14
    assert time.monotonic() - started < 2
    thread.join(5)
    assert not thread.is_alive()
    if size_delta:
        assert closed.is_set()


@pytest.mark.parametrize("status", [200, 503])
def test_api_body_elapsed_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    closed = threading.Event()

    def serve() -> None:
        with listener, listener.accept()[0] as peer:
            peer.settimeout(5)
            peer.recv(65536)
            peer.sendall(f"HTTP/1.1 {status} Test\r\nConnection: close\r\n\r\n".encode())
            try:
                while True:
                    peer.sendall(b" ")
                    time.sleep(0.02)
            except OSError:
                closed.set()

    settings = replace(_runner_settings(tmp_path), runner_api_base_url=f"http://127.0.0.1:{listener.getsockname()[1]}")
    monkeypatch.setattr(runner, "API_REQUEST_TIMEOUT_SECONDS", 0.15)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    started = time.monotonic()
    with pytest.raises(runner.RunnerApiError) as caught:
        runner.RunnerApiClient(settings).get_ticket("synthetic")
    assert caught.value.error_code == "transport_error"
    assert time.monotonic() - started < 2
    assert closed.wait(5)
    thread.join(5)


@pytest.mark.parametrize(
    "operation", ["has-session", "new-session", "kill-session", "discover", "cleanup-list", "cleanup-kill"],
)
def test_tmux_deadline_kills_and_reaps_owned_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    import subprocess
    import sys
    from typing import Any

    script = tmp_path / "fake_tmux.py"
    script.write_text(
        "import sys, time\n"
        "if sys.argv[1] == 'cleanup-kill' and sys.argv[2] == 'ls':\n"
        "    print('job-synthetic-01-test: synthetic')\n"
        "else:\n"
        "    print('synthetic private diagnostic', flush=True)\n"
        "    time.sleep(1)\n",
    )
    children: list[subprocess.Popen[str]] = []
    real_popen = subprocess.Popen

    def spawn(*args: Any, **kwargs: Any) -> subprocess.Popen[str]:
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", spawn)
    monkeypatch.setattr(runner, "TMUX_COMMAND_TIMEOUT_SECONDS", 0.15)
    settings = _runner_settings(tmp_path)
    executor = runner.TicketExecutor(settings=settings, api=runner.RunnerApiClient(settings),
                                     stop_event=threading.Event(), ticket_id="synthetic")
    supervisor = runner.OpsGateRunner(settings)

    def command(*args: str) -> list[str]:
        return [sys.executable, str(script), operation, *args]

    monkeypatch.setattr(executor, "_tmux_command", command)
    monkeypatch.setattr(supervisor, "_tmux_command", command)
    actions = {
        "has-session": lambda: executor._tmux_has_session("synthetic"),
        "new-session": lambda: executor._tmux_new_session(session_name="synthetic", script_path=tmp_path / "step"),
        "kill-session": lambda: executor._tmux_kill_session("synthetic"),
        "discover": supervisor._discover_ticket_ids_from_tmux,
        "cleanup-list": lambda: supervisor._kill_tmux_sessions_for_ticket("synthetic"),
        "cleanup-kill": lambda: supervisor._kill_tmux_sessions_for_ticket("synthetic"),
    }
    supervisor._write_state_file("synthetic")
    started = time.monotonic()
    with pytest.raises(runner.TmuxCommandTimeout, match="^tmux command timed out$"):
        actions[operation]()
    assert time.monotonic() - started < 2
    assert children and all(child.returncode is not None for child in children)
    assert supervisor._worker_state_path("synthetic").exists()


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
def test_api_accepts_connection_close_body(tmp_path: Path, framing: str) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]

    def serve() -> None:
        with listener, listener.accept()[0] as peer:
            peer.recv(65536)
            headers = {"length": b"Content-Length: 2\r\n", "chunked": b"Transfer-Encoding: chunked\r\n", "eof": b""}
            body = b"2\r\n{}\r\n0\r\n\r\n" if framing == "chunked" else b"{}"
            peer.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n" + headers[framing] + b"\r\n" + body)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    settings = replace(_runner_settings(tmp_path), runner_api_base_url=f"http://127.0.0.1:{port}")
    assert runner.RunnerApiClient(settings).get_ticket("synthetic") == {}
    thread.join(5)
    assert not thread.is_alive()


@pytest.mark.parametrize("status", [200, 409])
def test_api_rejects_truncated_content_length(tmp_path: Path, status: int) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]

    def serve() -> None:
        with listener, listener.accept()[0] as peer:
            peer.recv(65536)
            peer.sendall(f"HTTP/1.1 {status} Test\r\nContent-Length: 100\r\n\r\n{{}}".encode())

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    settings = replace(_runner_settings(tmp_path), runner_api_base_url=f"http://127.0.0.1:{port}")
    with pytest.raises(runner.RunnerApiError) as caught:
        runner.RunnerApiClient(settings).get_ticket("synthetic")
    assert (caught.value.status_code, caught.value.error_code) == (503, "transport_error")
    thread.join(5)
    assert not thread.is_alive()


@pytest.mark.parametrize("framing", ["headers", "chunk-extension", "trailers"])
@pytest.mark.parametrize("status", [200, 409])
def test_api_hard_deadline_covers_http_framing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, framing: str, status: int,
) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    closed = threading.Event()

    def serve() -> None:
        with listener, listener.accept()[0] as peer:
            peer.recv(65536)
            if framing == "headers":
                peer.sendall(f"HTTP/1.1 {status} Test\r\nX-Synthetic: ".encode())
            else:
                peer.sendall(f"HTTP/1.1 {status} Test\r\nTransfer-Encoding: chunked\r\n\r\n".encode())
                peer.sendall(b"1;" if framing == "chunk-extension" else b"2\r\n{}\r\n0\r\n")
            try:
                # Longer than the injected budget, while every recv remains active.
                for _ in range(100):
                    peer.sendall(b"X-Synthetic: x\r\n" if framing == "trailers" else b"x")
                    time.sleep(0.02)
            except OSError:
                closed.set()

    monkeypatch.setattr(runner, "API_REQUEST_TIMEOUT_SECONDS", 0.15)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    settings = replace(_runner_settings(tmp_path), runner_api_base_url=f"http://127.0.0.1:{port}")
    started = time.monotonic()
    with pytest.raises(runner.RunnerApiError) as caught:
        runner.RunnerApiClient(settings).get_ticket("synthetic")
    assert caught.value.error_code == "transport_error"
    assert time.monotonic() - started < 1
    assert closed.wait(5)
    thread.join(5)


def test_tmux_deadline_does_not_wait_for_inherited_pipes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    script = tmp_path / "inherited_pipe.py"
    finished = tmp_path / "descendant-finished"
    script.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', "
        "'import sys, time; from pathlib import Path; time.sleep(1.5); Path(sys.argv[1]).touch()', sys.argv[1]])\n"
        "time.sleep(30)\n",
    )
    monkeypatch.setattr(runner, "TMUX_COMMAND_TIMEOUT_SECONDS", 0.3)
    started = time.monotonic()
    with pytest.raises(runner.TmuxCommandTimeout):
        runner._run_tmux([sys.executable, str(script), str(finished)])
    assert time.monotonic() - started < 1
    # The owned client is gone; the stand-in server remains independent and
    # finishes naturally. Wait so the test leaves no synthetic process behind.
    deadline = time.monotonic() + 5
    while not finished.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert finished.exists()


def test_worker_tmux_cleanup_timeout_retains_recovery_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    supervisor = runner.OpsGateRunner(_runner_settings(tmp_path))
    api = FakeApi({"state": "running"})
    supervisor.api = api  # type: ignore[assignment]
    supervisor._write_state_file("synthetic")
    monkeypatch.setattr(runner, "TMUX_COMMAND_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(supervisor, "_tmux_command", lambda *args: [sys.executable, "-c", "import time; time.sleep(1)"])

    def interrupted(*args, **kwargs) -> None:
        raise runner.TmuxCommandTimeout("tmux command timed out")

    monkeypatch.setattr(runner.TicketExecutor, "run", interrupted)
    supervisor._run_worker(ticket_id="synthetic", initial_ticket=api.ticket)
    assert supervisor._worker_state_path("synthetic").exists()
    assert supervisor._worker_cleanup["synthetic"] is False
    assert api.ticket["state"] == "running"
    assert not api.updates


def test_api_watchdog_preserves_ssl_wrapper() -> None:
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client, peer = socket.socketpair()
    with peer, context.wrap_socket(client, server_hostname="synthetic.invalid", do_handshake_on_connect=False) as tls:
        runner._shutdown_api_socket(tls)
        # Raw transport shutdown interrupts TLS with an OSError. Calling the
        # SSLSocket override discards its wrapper and loses the transport error.
        with pytest.raises(OSError):
            tls.do_handshake()


@pytest.mark.parametrize("interruption", [OSError, ValueError, AttributeError])
def test_api_https_watchdog_normalizes_interrupted_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interruption: type[Exception],
) -> None:
    import ssl
    from typing import Any

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client, peer = socket.socketpair()
    tls = context.wrap_socket(client, server_hostname="synthetic.invalid", do_handshake_on_connect=False)
    # Only the watchdog may unblock this handshake, not a competing socket timeout.
    monkeypatch.setattr(tls, "settimeout", lambda _: None)

    class Connection:
        sock = tls

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def connect(self) -> None:
            pass

        def request(self, *args: Any) -> None:
            pass

        def getresponse(self) -> Any:
            # The synthetic peer does not speak TLS. The watchdog must interrupt
            # this public SSL API and normalize the resulting transport failure.
            try:
                tls.do_handshake()
            except OSError:
                raise interruption("synthetic private TLS diagnostic") from None
            raise AssertionError("synthetic handshake completed")

        def close(self) -> None:
            tls.close()

    monkeypatch.setattr(runner, "API_REQUEST_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(runner, "HTTPSConnection", Connection)
    settings = replace(_runner_settings(tmp_path), runner_api_base_url="https://synthetic.invalid")
    with peer:
        started = time.monotonic()
        with pytest.raises(runner.RunnerApiError) as caught:
            runner.RunnerApiClient(settings).get_ticket("synthetic")
        assert time.monotonic() - started < 1
        assert (caught.value.status_code, caught.value.error_code) == (503, "transport_error")
        assert "private" not in str(caught.value)
