"""
GhostTunnel IPC Server — Unix Domain Socket
============================================
Fixes CRIT-04: Replaces the stub CLI panic trigger with real IPC.

Protocol: newline-delimited JSON
  Request:  {"cmd": "panic"} | {"cmd": "panic-disable"} | {"cmd": "status"}
  Response: {"ok": true, ...} | {"ok": false, "error": "..."}

Socket:  /run/ghosttunnel/ctrl.sock (permissions 0o600, root only)

Security hardening (SEC-IPC-01):
  - SO_PEERCRED validation: only UID 0 (root) may send commands.
  - JSON decode errors on send_command() are caught and re-raised as
    ConnectionRefusedError so callers handle them uniformly.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import struct
import threading
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

SOCKET_PATH = "/run/ghosttunnel/ctrl.sock"
_SOCKET_PERMS = 0o600          # root read/write only
_RECV_LIMIT = 4096
_CLIENT_TIMEOUT = 5.0
_MAX_CHUNKS = 64  # Maximum recv() calls per message (prevents slow-loris)


class IpcServer:
    """
    Lightweight IPC server running as a daemon thread inside ghostd.
    Handlers are callables that return a dict merged into the JSON response.
    """

    def __init__(self, handlers: dict[str, Callable[[], dict]]) -> None:
        self.handlers = handlers
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        sock_path = Path(SOCKET_PATH)
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        if sock_path.exists():
            sock_path.unlink()

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(sock_path))
        # Set permissions immediately after bind — before listen() — to
        # eliminate the TOCTOU window where the socket is world-accessible.
        os.chmod(str(sock_path), _SOCKET_PERMS)
        self._sock.listen(5)
        self._sock.settimeout(1.0)   # allows clean shutdown

        self._running = True
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="ipc-server"
        )
        self._thread.start()
        logger.info("IPC server listening at %s", SOCKET_PATH)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        Path(SOCKET_PATH).unlink(missing_ok=True)
        logger.info("IPC server stopped.")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _serve(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(conn,), daemon=True
            ).start()

    @staticmethod
    def _check_peer_uid(conn: socket.socket) -> bool:
        """
        SEC-IPC-01: Verify the connecting peer is UID 0 (root).
        Uses SO_PEERCRED which is atomic on Linux — cannot be spoofed.
        Returns True if authorized, False otherwise.
        """
        try:
            # SO_PEERCRED returns struct { pid_t pid; uid_t uid; gid_t gid; }
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, _ = struct.unpack("3i", cred)
            return uid == 0
        except (OSError, struct.error):
            # If we cannot verify, deny by default (FAIL CLOSED principle)
            return False

    def _handle(self, conn: socket.socket) -> None:
        try:
            with conn:
                conn.settimeout(_CLIENT_TIMEOUT)

                # SEC-IPC-01: Reject non-root connections immediately
                if not self._check_peer_uid(conn):
                    self._send(conn, {"ok": False, "error": "unauthorized: root required"})
                    logger.warning("IPC: rejected connection from non-root peer.")
                    return

                # Read until newline to handle TCP stream fragmentation
                raw = self._recv_line(conn)
                if raw is None:
                    self._send(conn, {"ok": False, "error": "empty request"})
                    return
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    self._send(conn, {"ok": False, "error": "invalid JSON"})
                    return

                cmd = str(msg.get("cmd", ""))
                handler = self.handlers.get(cmd)
                if not handler:
                    self._send(conn, {"ok": False, "error": f"unknown command: {cmd}"})
                    return

                try:
                    result = handler()
                    self._send(conn, {"ok": True, **(result or {})})
                except Exception as exc:
                    logger.warning("IPC handler error for cmd=%s: %s", cmd, exc)
                    self._send(conn, {"ok": False, "error": "internal handler error"})
        except Exception as exc:
            logger.debug("IPC connection closed unexpectedly: %s", exc)

    @staticmethod
    def _recv_line(conn: socket.socket) -> str | None:
        """
        Read from socket until a newline or the byte/chunk limits are reached.
        _MAX_CHUNKS prevents a slow-loris style attack where an adversary sends
        data 1 byte at a time to keep the handler thread busy indefinitely.
        """
        buf = b""
        chunks = 0
        while len(buf) < _RECV_LIMIT and chunks < _MAX_CHUNKS:
            try:
                chunk = conn.recv(min(256, _RECV_LIMIT - len(buf)))
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            chunks += 1
            if b"\n" in buf:
                break
        text = buf.decode("utf-8", errors="replace").strip()
        return text if text else None

    @staticmethod
    def _send(conn: socket.socket, data: dict) -> None:
        try:
            conn.sendall(json.dumps(data).encode("utf-8") + b"\n")
        except OSError:
            pass


# ------------------------------------------------------------------
# Client helper — used by ghostctl
# ------------------------------------------------------------------

def send_command(cmd: str, timeout: float = 5.0) -> dict:
    """
    Send a command to the running daemon via IPC socket.
    Returns the parsed JSON response dict, or raises ConnectionRefusedError.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect(SOCKET_PATH)
        except FileNotFoundError:
            raise ConnectionRefusedError("GhostTunnel daemon is not running (socket not found).")
        # Send request terminated by newline so the server can detect end-of-message
        s.sendall(json.dumps({"cmd": cmd}).encode("utf-8") + b"\n")
        # Read response until newline
        buf = b""
        chunks = 0
        while len(buf) < _RECV_LIMIT and chunks < _MAX_CHUNKS:
            chunk = s.recv(256)
            if not chunk:
                break
            buf += chunk
            chunks += 1
            if b"\n" in buf:
                break
    raw = buf.decode("utf-8", errors="replace").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConnectionRefusedError(f"Daemon returned malformed response: {raw[:80]!r}") from exc
