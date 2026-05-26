import json
import logging
import urllib.request
import urllib.error
from pathlib import Path

try:
    from PyQt6.QtCore import QThread, pyqtSignal
except ImportError:
    pass

logger = logging.getLogger(__name__)

class LeakWorker(QThread):
    """
    Polls public IP/DNS information to detect leaks.
    Runs entirely in user-space to avoid root HTTP requests.
    """
    leak_data_updated = pyqtSignal(dict)

    def __init__(self, interval_ms: int = 10000, parent=None):
        super().__init__(parent)
        self.interval_ms = interval_ms
        self._running = True

    def run(self) -> None:
        while self._running:
            data = {
                "public_ip": "Unknown",
                "country": "Unknown",
                "org": "Unknown",
                "dns_servers": []
            }
            
            # 1. Fetch public IP info from ipinfo.io
            try:
                # We use ipinfo.io as it provides a clean, rate-limit friendly JSON response
                # Note: For strict OPSEC, some users might prefer am.i.mullvad.net or custom endpoints.
                req = urllib.request.Request("https://ipinfo.io/json", headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5.0) as response:
                    if response.status == 200:
                        ip_info = json.loads(response.read().decode('utf-8'))
                        data["public_ip"] = ip_info.get("ip", "Unknown")
                        data["country"] = ip_info.get("country", "Unknown")
                        data["org"] = ip_info.get("org", "Unknown")
            except Exception as e:
                logger.debug(f"LeakWorker IP fetch failed: {e}")
                data["public_ip"] = "Error"

            # 2. Parse /etc/resolv.conf to find active DNS servers
            try:
                resolv_path = Path("/etc/resolv.conf")
                if resolv_path.exists():
                    dns_servers = []
                    lines = resolv_path.read_text(encoding="utf-8").splitlines()
                    for line in lines:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_servers.append(parts[1])
                    data["dns_servers"] = dns_servers
            except Exception as e:
                logger.debug(f"LeakWorker DNS fetch failed: {e}")

            if self._running:
                self.leak_data_updated.emit(data)
                
            # Sleep in small increments to allow responsive shutdown
            slept = 0
            while self._running and slept < self.interval_ms:
                self.msleep(100)
                slept += 100

    def stop(self) -> None:
        self._running = False
        self.quit()
        self.wait(2000)
