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

CTRL_SOCKET_PATH = "/run/ghosttunnel/ctrl.sock"
STATUS_SOCKET_PATH = "/run/ghosttunnel/status.sock"
_RECV_LIMIT = 4096
_CLIENT_TIMEOUT = 5.0
_MAX_CHUNKS = 64

class IpcServer:
    def __init__(self, handlers: dict[str, Callable[[dict], dict]]) -> None:
        self.handlers = handlers
        self._ctrl_sock: socket.socket | None = None
        self._status_sock: socket.socket | None = None
        self._running = False
        self._status_clients: list[socket.socket] = []
        self._status_lock = threading.Lock()

    def start(self) -> None:
        import grp
        try:
            gid = grp.getgrnam("ghosttunnel").gr_gid  # type: ignore
        except KeyError:
            logger.warning("Group 'ghosttunnel' not found. Using root GID.")
            gid = 0

        def bind_sock(path_str: str, perms: int) -> socket.socket:
            p = Path(path_str)
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists(): p.unlink()
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # type: ignore
            s.bind(path_str)
            os.chmod(path_str, perms)
            try:
                os.chown(path_str, -1, gid)  # type: ignore
            except OSError as exc:
                logger.warning("Failed to chown socket %s: %s", path_str, exc)
            s.listen(5)
            s.settimeout(1.0)
            return s

        self._ctrl_sock = bind_sock(CTRL_SOCKET_PATH, 0o660)
        self._status_sock = bind_sock(STATUS_SOCKET_PATH, 0o664)

        self._running = True
        threading.Thread(target=self._serve_ctrl, daemon=True, name="ipc-ctrl").start()
        threading.Thread(target=self._serve_status, daemon=True, name="ipc-status").start()
        logger.info("IPC server listening. Ctrl: %s | Status: %s", CTRL_SOCKET_PATH, STATUS_SOCKET_PATH)

    def stop(self) -> None:
        self._running = False
        for s in (self._ctrl_sock, self._status_sock):
            if s:
                try: s.close()
                except OSError as exc: logger.warning("Error closing socket: %s", exc)
        Path(CTRL_SOCKET_PATH).unlink(missing_ok=True)
        Path(STATUS_SOCKET_PATH).unlink(missing_ok=True)

    def broadcast(self, data: dict) -> None:
        payload = json.dumps(data).encode("utf-8") + b"\n"
        with self._status_lock:
            dead = []
            for c in self._status_clients:
                try:
                    c.sendall(payload)
                except OSError:
                    dead.append(c)
            for c in dead:
                self._status_clients.remove(c)
                try: c.close()
                except OSError as exc: logger.warning("Error closing dead client: %s", exc)

    def _serve_status(self) -> None:
        """
        Accepts connections on the status Unix Domain Socket, performs GID verification,
        sets a socket timeout, and registers clients for status broadcasts.
        """
        while self._running and self._status_sock:
            try:
                conn, _ = self._status_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            
            try:
                conn.settimeout(1.0)
                if not self._check_peer_gid(conn):
                    try:
                        conn.close()
                    except OSError as exc:
                        logger.warning("Error closing unauthorized client: %s", exc)
                    continue
            except Exception as exc:
                logger.error("Error configuring status socket client: %s", exc)
                try:
                    conn.close()
                except OSError as exc:
                    logger.warning("Error closing client on exception: %s", exc)
                continue

            with self._status_lock:
                self._status_clients.append(conn)

    def _serve_ctrl(self) -> None:
        """
        Accepts connections on the control Unix Domain Socket and spawns a thread to
        handle each command.
        """
        while self._running and self._ctrl_sock:
            try:
                conn, _ = self._ctrl_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_ctrl, args=(conn,), daemon=True).start()

    @staticmethod
    def _check_peer_gid(conn: socket.socket) -> bool:
        """
        Retrieves peer GID credentials from Unix Domain Socket credentials and verifies
        if the client belongs to the authorized 'ghosttunnel' group or is root.
        """
        try:
            import grp
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))  # type: ignore
            _, peer_uid, peer_gid = struct.unpack("3i", cred)
            if peer_uid == 0:
                return True
            gt_gid = grp.getgrnam("ghosttunnel").gr_gid  # type: ignore
            return peer_gid == gt_gid
        except Exception:
            logger.debug("Failed checking peer credentials")
            return False

    def _handle_ctrl(self, conn: socket.socket) -> None:
        """
        Processes client commands on the control socket connection.

        Args:
            conn: The client socket connection.
        """
        try:
            with conn:
                conn.settimeout(_CLIENT_TIMEOUT)
                if not self._check_peer_gid(conn):
                    self._send(conn, {"ok": False, "error": "unauthorized: ghosttunnel group required"})
                    return
                raw = self._recv_line(conn)
                if not raw:
                    self._send(conn, {"ok": False, "error": "empty request"})
                    return
                try:
                    msg = json.loads(raw)
                    if not isinstance(msg, dict):
                        self._send(conn, {"ok": False, "error": "invalid JSON format, dict expected"})
                        return
                except json.JSONDecodeError:
                    self._send(conn, {"ok": False, "error": "invalid JSON"})
                    return

                action = str(msg.get("action", ""))
                handler = self.handlers.get(action)
                if not handler:
                    self._send(conn, {"ok": False, "error": f"unknown action: {action}"})
                    return

                try:
                    payload = msg.get("payload", {})
                    result = handler(payload)
                    self._send(conn, {"ok": True, **(result or {})})
                except Exception as exc:
                    logger.error("IPC command execution failed: %s", exc)
                    self._send(conn, {"ok": False, "error": "internal handler error"})
        except Exception as exc:
            logger.error("IPC connection error: %s", exc)

    @staticmethod
    def _recv_line(conn: socket.socket) -> str | None:
        buf = b""
        chunks = 0
        while len(buf) < _RECV_LIMIT and chunks < _MAX_CHUNKS:
            try:
                chunk = conn.recv(min(256, _RECV_LIMIT - len(buf)))
            except OSError: break
            if not chunk: break
            buf += chunk
            chunks += 1
            if b"\n" in buf: break
        text = buf.decode("utf-8", errors="replace").strip()
        return text if text else None

    @staticmethod
    def _send(conn: socket.socket, data: dict) -> None:
        try:
            conn.sendall(json.dumps(data).encode("utf-8") + b"\n")
        except OSError as exc:
            logger.warning("Error sending data to client: %s", exc)

def send_command(action: str, payload: dict | None = None, timeout: float = 5.0) -> dict:
    """Send a command to the daemon via the control Unix socket."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # type: ignore
        s.settimeout(timeout)
        try:
            s.connect(CTRL_SOCKET_PATH)
        except (FileNotFoundError, ConnectionError) as exc:
            raise ConnectionRefusedError(f"GhostTunnel daemon is not reachable: {exc}") from exc
        msg = {"action": action, "payload": payload or {}, "token": ""}
        try:
            s.sendall(json.dumps(msg).encode("utf-8") + b"\n")
        except (OSError, ConnectionError) as exc:
            raise ConnectionRefusedError(f"Failed to send IPC command: {exc}") from exc
        buf = b""
        chunks = 0
        while len(buf) < _RECV_LIMIT and chunks < _MAX_CHUNKS:
            try: chunk = s.recv(256)
            except OSError: break
            if not chunk: break
            buf += chunk
            chunks += 1
            if b"\n" in buf: break
    raw = buf.decode("utf-8", errors="replace").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConnectionRefusedError(f"Daemon returned malformed response.") from exc
