#!/usr/bin/env bash
# GhostTunnel Dependencies Installer for Debian/Ubuntu (2026 Edition)
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo ./scripts/install_deps.sh)"
  exit 1
fi

echo "[+] Updating apt repositories..."
apt-get update -qq

echo "[+] Installing system requirements..."
apt-get install -y -qq software-properties-common curl build-essential libnftables1 python3-nftables

echo "[+] Ensuring Python 3.14 is available..."
if ! command -v python3.14 &> /dev/null; then
    echo "[*] Adding deadsnakes PPA for Python 3.14..."
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -qq
    apt-get install -y -qq python3.14 python3.14-venv python3.14-dev
else
    echo "[OK] Python 3.14 already installed."
fi

echo "[+] Installing uv (Astral) package manager..."
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # In a root script, the installer might put it in /root/.cargo/bin. We link it for everyone.
    if [ -f "/root/.cargo/bin/uv" ]; then
        ln -sf /root/.cargo/bin/uv /usr/local/bin/uv
    fi
else
    echo "[OK] uv already installed."
fi

echo "[+] GhostTunnel dependencies installed successfully."
echo "[+] You can now run: uv pip install -e \".[dev]\""
