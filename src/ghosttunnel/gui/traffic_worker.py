import logging
import time
from pathlib import Path

try:
    from PyQt6.QtCore import QThread, pyqtSignal
except ImportError:
    pass

logger = logging.getLogger(__name__)

class TrafficWorker(QThread):
    """
    Polls /proc/net/dev to calculate traffic rates per interface.
    """
    traffic_updated = pyqtSignal(dict)

    def __init__(self, interval_ms: int = 1000, parent=None):
        super().__init__(parent)
        self.interval_ms = interval_ms
        self._running = True
        self._last_stats = {}
        self._last_time = 0.0

    def run(self):
        while self._running:
            current_time = time.time()
            current_stats = self._read_net_dev()
            
            if self._last_time > 0 and current_stats:
                dt = current_time - self._last_time
                if dt > 0:
                    rates = {}
                    for iface, (rx_bytes, tx_bytes) in current_stats.items():
                        if iface in self._last_stats:
                            last_rx, last_tx = self._last_stats[iface]
                            rx_rate = (rx_bytes - last_rx) / dt
                            tx_rate = (tx_bytes - last_tx) / dt
                            
                            # Only report interfaces that are actually transmitting/receiving to reduce noise
                            # or report all but the GUI handles it. Let's report all that exist.
                            rates[iface] = {
                                "rx_bytes_sec": rx_rate,
                                "tx_bytes_sec": tx_rate,
                                "total_rx": rx_bytes,
                                "total_tx": tx_bytes
                            }
                    self.traffic_updated.emit(rates)

            self._last_stats = current_stats
            self._last_time = current_time

            slept = 0
            while self._running and slept < self.interval_ms:
                self.msleep(100)
                slept += 100

    def _read_net_dev(self) -> dict:
        """Reads /proc/net/dev and returns {iface: (rx_bytes, tx_bytes)}"""
        stats = {}
        try:
            path = Path("/proc/net/dev")
            if not path.exists():
                return stats
            lines = path.read_text(encoding="utf-8").splitlines()
            # Skip header lines (usually the first 2)
            for line in lines[2:]:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface = iface.strip()
                fields = data.split()
                if len(fields) >= 9:
                    rx_bytes = int(fields[0])
                    tx_bytes = int(fields[8])
                    stats[iface] = (rx_bytes, tx_bytes)
        except Exception as e:
            logger.debug(f"Failed to read /proc/net/dev: {e}")
        return stats

    def stop(self):
        self._running = False
        self.quit()
        self.wait(2000)
