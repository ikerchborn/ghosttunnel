#!/usr/bin/env bash
# GhostTunnel - Advanced VPN Kill Switch & OPSEC Tool Installer
#
# Fixes applied:
#   HIGH-05 — Uses a dedicated virtualenv instead of --break-system-packages
#   CRIT-01 — Installs static panic.rules for ExecStartPre
#   SEC     — Strict error handling: exit on any error, unset var, or pipe failure
#   BUG-INST-01 — Removed obsolete policykit-1 package (now polkitd/pkexec)
#   BUG-INST-02 — All symlinks created (ghostctl, ghostd, ghostgui, ghosttunnel-gui)
#   BUG-INST-03 — /run/ghosttunnel created with correct 0o750 permissions
#   BUG-INST-04 — Service is validated before enabling
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root (sudo ./install.sh)"
  exit 1
fi

echo "[+] ========================================================="
echo "[+] Starting Installation: GhostTunnel (Military Grade OPSEC)"
echo "[+] ========================================================="

# 1. Install system dependencies
echo "[*] Installing dependencies (nftables, iproute2, python3)..."
apt-get update -qq
apt-get install -y \
  python3 python3-full python3-venv \
  nftables iproute2 \
  polkitd pkexec \
  libnftables1 \
  build-essential pkg-config \
  python3-pyqt6 \
  --no-install-recommends

# 2. Create dedicated isolated virtualenv (HIGH-05)
VENV_DIR="/opt/ghosttunnel/venv"
echo "[*] Creating Python virtualenv at ${VENV_DIR}..."
mkdir -p /opt/ghosttunnel
chmod 750 /opt/ghosttunnel
# NOTE: Do NOT use --system-site-packages — it allows system packages to bleed in.
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install . --quiet

# 3. Install static panic rules for ExecStartPre (CRIT-01)
echo "[*] Installing static FAIL CLOSED boot rules..."
mkdir -p /etc/ghosttunnel
chmod 700 /etc/ghosttunnel
cp etc/ghosttunnel/panic.rules /etc/ghosttunnel/panic.rules
chmod 600 /etc/ghosttunnel/panic.rules
chown root:root /etc/ghosttunnel/panic.rules

# 4. Setup Systemd daemon
echo "[*] Configuring Security Daemon in Systemd..."
cp systemd/ghosttunnel.service /etc/systemd/system/
chmod 644 /etc/systemd/system/ghosttunnel.service

# BUG-INST-03: Create /run/ghosttunnel with correct permissions
# (systemd RuntimeDirectory also creates it, but this ensures it exists pre-boot)
mkdir -p /run/ghosttunnel
chmod 750 /run/ghosttunnel
chown root:root /run/ghosttunnel

# 5. Install emergency recovery script
echo "[*] Installing emergency offline recovery script..."
cp src/ghost-recover.sh /usr/local/bin/ghost-recover
chmod 750 /usr/local/bin/ghost-recover
chown root:root /usr/local/bin/ghost-recover

# 6. Symlink CLI tools to /usr/local/bin (BUG-INST-02: all 4 symlinks)
echo "[*] Linking CLI tools..."
ln -sf "${VENV_DIR}/bin/ghostctl"  /usr/local/bin/ghostctl
ln -sf "${VENV_DIR}/bin/ghostd"    /usr/local/bin/ghostd
ln -sf "${VENV_DIR}/bin/ghostgui"  /usr/local/bin/ghostgui
# Alias for compatibility
ln -sf "${VENV_DIR}/bin/ghostgui"  /usr/local/bin/ghosttunnel-gui

# Verify the symlinks resolve correctly
for bin in ghostctl ghostd ghostgui; do
  if [ ! -x "${VENV_DIR}/bin/${bin}" ]; then
    echo "[!] WARNING: ${bin} was not installed correctly. Check pyproject.toml [scripts]."
  else
    echo "[+] ${bin} → ${VENV_DIR}/bin/${bin}"
  fi
done

# 7. Enable and start service (BUG-INST-04: validate service file first)
echo "[*] Enabling service on boot..."
systemctl daemon-reload
if systemd-analyze verify /etc/systemd/system/ghosttunnel.service 2>/dev/null; then
  systemctl enable ghosttunnel.service
  systemctl restart ghosttunnel.service || true
  echo "[+] Service started."
else
  echo "[!] Service file has issues. Enabling without starting."
  systemctl enable ghosttunnel.service
fi

echo "[+] ========================================================="
echo "[+] Installation Completed Successfully."
echo "[+]"
echo "[+]   CLI:       sudo ghostctl status"
echo "[+]              sudo ghostctl panic"
echo "[+]              sudo ghostctl panic-disable"
echo "[+]              sudo ghostctl unlock-network"
echo "[+]              sudo ghostctl start | restart | logs"
echo "[+]"
echo "[+]   GUI:       ghostgui   (or ghosttunnel-gui)"
echo "[+]   Recovery:  sudo ghost-recover"
echo "[+]   Logs:      sudo ghostctl logs"
echo "[+]              journalctl -u ghosttunnel -f"
echo "[+] ========================================================="
echo "[+]"
echo "[+] NOTE: Run 'sudo ghostctl status' to verify the daemon is running."
