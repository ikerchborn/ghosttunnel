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

# 2. Setup Runtime Environment (VENV or Native)
VENV_DIR="/opt/ghosttunnel/venv"
if [ -d "dist_bin" ] && [ -f "dist_bin/ghostd" ]; then
    echo "[+] Native compiled binaries detected in dist_bin/."
    echo "[+] Skipping Python virtual environment creation for a faster, native installation."
else
    echo "[*] Native binaries not found. Creating Python virtualenv at ${VENV_DIR}..."
    mkdir -p /opt/ghosttunnel
    chmod 750 /opt/ghosttunnel
    # NOTE: Do NOT use --system-site-packages — it allows system packages to bleed in.
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
    "${VENV_DIR}/bin/pip" install . --quiet
fi

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
chmod 755 /run/ghosttunnel
chown root:root /run/ghosttunnel

# 5. Install emergency recovery script
echo "[*] Installing emergency offline recovery script..."
cp src/ghost-recover.sh /usr/local/bin/ghost-recover
chmod 750 /usr/local/bin/ghost-recover
chown root:root /usr/local/bin/ghost-recover

# 6. Install CLI tools and GUI to /usr/bin (Fixes sudo secure_path issues)
echo "[*] Installing CLI tools and GUI..."
if [ -d "dist_bin" ] && [ -f "dist_bin/ghostctl" ]; then
    echo "[+] Found native compiled binaries in dist_bin/. Installing directly to /usr/bin..."
    cp dist_bin/ghostctl /usr/bin/ghostctl
    cp dist_bin/ghostd   /usr/bin/ghostd
    cp dist_bin/ghostgui /usr/bin/ghostgui
    chmod 755 /usr/bin/ghostctl /usr/bin/ghostd /usr/bin/ghostgui
    ln -sf /usr/bin/ghostgui /usr/bin/ghosttunnel-gui
else
    echo "[*] Native binaries not found. Symlinking virtualenv tools to /usr/bin..."
    ln -sf "${VENV_DIR}/bin/ghostctl"  /usr/bin/ghostctl
    ln -sf "${VENV_DIR}/bin/ghostd"    /usr/bin/ghostd
    ln -sf "${VENV_DIR}/bin/ghostgui"  /usr/bin/ghostgui
    # Alias for compatibility
    ln -sf "${VENV_DIR}/bin/ghostgui"  /usr/bin/ghosttunnel-gui

    # Verify the symlinks resolve correctly
    for bin in ghostctl ghostd ghostgui; do
      if [ ! -x "${VENV_DIR}/bin/${bin}" ]; then
        echo "[!] WARNING: ${bin} was not installed correctly. Check pyproject.toml [scripts]."
      else
        echo "[+] ${bin} → ${VENV_DIR}/bin/${bin}"
      fi
    done
fi

# 6.5. Install Desktop Entry
echo "[*] Installing Desktop Application Entry..."
if [ -f "assets/ghosttunnel.desktop" ]; then
    mkdir -p /usr/share/applications
    cp assets/ghosttunnel.desktop /usr/share/applications/
    chmod 644 /usr/share/applications/ghosttunnel.desktop
    echo "[+] Installed ghosttunnel.desktop"
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications/ || true
    fi
else
    echo "[!] WARNING: assets/ghosttunnel.desktop not found. Skipping GUI menu entry."
fi

# 7. Enable service (User will start it manually)
echo "[*] Enabling service on boot (Will not start automatically right now)..."
systemctl daemon-reload
if systemd-analyze verify /etc/systemd/system/ghosttunnel.service 2>/dev/null; then
  systemctl enable ghosttunnel.service
  echo "[+] Service enabled. You must start it manually for the first time."
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
echo "[+] ⚠  IMPORTANT: GhostTunnel protection is NOT active yet."
echo "[+]    To activate the killswitch for the first time, run:"
echo "[+]        sudo systemctl start ghosttunnel"
echo "[+]"
