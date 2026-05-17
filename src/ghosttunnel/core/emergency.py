"""
GhostTunnel Emergency Controller
==================================
Fixes CRIT-03: Panic state now persists across daemon restarts via a lock file.
A daemon restart no longer silently clears an active panic, preventing stealth
post-crash leak resumption.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PANIC_LOCK_PATH = "/run/ghosttunnel/PANIC.lock"


class EmergencyController:
    def __init__(self) -> None:
        # Restore panic state from a previous run if the lock file exists.
        self.panic_mode: bool = self._read_lock()
        if self.panic_mode:
            logger.critical(
                "PANIC lock file found at startup (%s). "
                "Resuming panic mode. Run 'ghostctl panic-disable' to clear.",
                PANIC_LOCK_PATH,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def trigger_panic(self, reason: str) -> None:
        if not self.panic_mode:
            logger.critical("PANIC MODE TRIGGERED: %s", reason)
        self.panic_mode = True
        self._write_lock(reason)

    def disable_panic(self) -> None:
        if self.panic_mode:
            logger.info("Panic mode disabled by operator.")
        self.panic_mode = False
        self._remove_lock()

    def is_panic(self) -> bool:
        return self.panic_mode

    # ------------------------------------------------------------------
    # Lock file helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _write_lock(reason: str) -> None:
        path = Path(PANIC_LOCK_PATH)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(reason[:512], encoding="utf-8")
        except OSError as exc:
            logger.error("Could not write panic lock file: %s", exc)

    @staticmethod
    def _remove_lock() -> None:
        try:
            Path(PANIC_LOCK_PATH).unlink(missing_ok=True)
        except OSError as exc:
            logger.error("Could not remove panic lock file: %s", exc)

    @staticmethod
    def _read_lock() -> bool:
        return Path(PANIC_LOCK_PATH).exists()
