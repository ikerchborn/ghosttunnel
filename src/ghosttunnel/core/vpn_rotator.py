"""
GhostTunnel VPN Rotator
=========================
Fixes applied:
  Bug fix — reset() now clears both retries AND last_rotation so a stable
            reconnection fully resets the cooldown window for future events.
"""
import logging
import time
from ghosttunnel.vpn import get_adapters

logger = logging.getLogger(__name__)


class VpnRotator:
    def __init__(self, settings):
        self.settings = settings
        self.adapters = {adapter.name: adapter for adapter in get_adapters()}
        self.last_rotation: float = 0.0
        self.cooldown_seconds: float = 15.0
        self.retries: int = 0
        self.max_retries: int = 3

    def rotate(self, current_provider: str) -> bool:
        """
        Attempts to rotate the VPN connection to restore service.
        Returns True if a rotation was triggered, False if blocked by
        cooldown or max retries.
        """
        if not self.settings.auto_rotate:
            logger.info("Auto-rotate is disabled in config.")
            return False

        now = time.monotonic()
        if now - self.last_rotation < self.cooldown_seconds:
            remaining = self.cooldown_seconds - (now - self.last_rotation)
            logger.warning("Rotation blocked by cooldown (%.0fs remaining).", remaining)
            return False

        if self.retries >= self.max_retries:
            logger.critical(
                "Max rotation retries (%d) reached. All nodes failed. "
                "Entering FAIL CLOSED panic mode.",
                self.max_retries,
            )
            return False

        self.last_rotation = now
        self.retries += 1

        logger.info(
            "Initiating VPN rotation (attempt %d/%d)...",
            self.retries, self.max_retries,
        )

        # Try to reconnect the current provider first
        adapter = self.adapters.get(current_provider)
        if adapter:
            success = adapter.reconnect()
            if success:
                logger.info("VPN reconnect command issued for %s.", current_provider)
                return True

        # Fallback: iterate priority list
        for provider in self.settings.vpn_priority:
            if provider != current_provider and provider in self.adapters:
                logger.info("Attempting fallback provider: %s", provider)
                if self.adapters[provider].reconnect():
                    return True

        logger.error("All rotation attempts failed.")
        return False

    def reset(self) -> None:
        """
        Full reset after a stable VPN connection is established.
        Clears both retries and last_rotation so the next failure gets
        a fresh set of attempts without an artificial cooldown delay.
        """
        if self.retries > 0 or self.last_rotation > 0:
            logger.debug("VPN stable — rotation state reset.")
        self.retries = 0
        self.last_rotation = 0.0
