#!/usr/bin/env bash
# GhostTunnel - Advanced VPN Kill Switch & OPSEC Tool Installer
#
# Fixes applied:
#   HIGH-05 — Uses a dedicated virtualenv instead of --break-system-packages
#   CRIT-01 — Installs static panic.rules for ExecStartPre
#   SEC     — Strict error handling: exit on any error, unset var, or pipe failure
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
apt-get install -y python3 python3-full python3-venv nftables iproute2 polkitd pkexec libnftables1 build-essential pkg-config

# 2. Create dedicated isolated virtualenv (HIGH-05)
VENV_DIR="/opt/ghosttunnel/venv"
echo "[*] Creating Python virtualenv at ${VENV_DIR}..."
mkdir -p /opt/ghosttunnel
# NOTE: Do NOT use --system-site-packages — it allows system packages to bleed
# into the venv and defeats the purpose of dependency isolation.
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install .

# 3. Install static panic rules for ExecStartPre (CRIT-01)
echo "[*] Installing static FAIL CLOSED boot rules..."
mkdir -p /etc/ghosttunnel
chmod 700 /etc/ghosttunnel
cp etc/ghosttunnel/panic.rules /etc/ghosttunnel/panic.rules
chmod 600 /etc/ghosttunnel/panic.rules

# 4. Setup Systemd daemon
echo "[*] Configuring Security Daemon in Systemd..."
cp systemd/ghosttunnel.service /etc/systemd/system/
chmod 644 /etc/systemd/system/ghosttunnel.service

# Setup state directory with strict permissions
mkdir -p /run/ghosttunnel
chmod 750 /run/ghosttunnel

# 5. Install emergency recovery script (GUI optional)
echo "[*] Note: For GUI mode (ghostgui), install PyQt6 via:"
echo "    sudo apt-get install -y python3-pyqt6"

# 5. Install emergency recovery script
echo "[*] Installing emergency offline recovery script..."
cp src/ghost-recover.sh /usr/local/bin/ghost-recover
chmod +x /usr/local/bin/ghost-recover

# 6. Symlink CLI to /usr/local/bin for convenience
echo "[*] Linking CLI tools..."
ln -sf "${VENV_DIR}/bin/ghostctl" /usr/local/bin/ghostctl
ln -sf "${VENV_DIR}/bin/ghostd" /usr/local/bin/ghostd

# 7. Enable and start service
echo "[*] Enabling service on boot..."
systemctl daemon-reload
systemctl enable ghosttunnel.service
systemctl restart ghosttunnel.service

echo "[+] ========================================================="
echo "[+] Installation Completed Successfully."
echo "[+]"
echo "[+]   CLI:      ghostctl status | panic | panic-disable | unlock-network"
echo "[+]   Recovery: sudo ghost-recover"
echo "[+]   Logs:     journalctl -u ghosttunnel -f"
echo "[+] ========================================================="
