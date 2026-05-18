#!/usr/bin/env bash
# GhostTunnel - Native Binary Compiler using PyInstaller
set -euo pipefail

echo "[+] ========================================================="
echo "[+] GhostTunnel Native Binary Compiler"
echo "[+] ========================================================="

# Ensure we are in the project root
if [ ! -f "pyproject.toml" ]; then
    echo "[!] Error: Must be run from the GhostTunnel project root."
    exit 1
fi

echo "[*] Setting up temporary build environment..."
VENV_DIR="build_venv"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "[*] Installing dependencies..."
pip install --upgrade pip --quiet
pip install pyinstaller PyQt6 --quiet
pip install . --quiet

# Define dist directory
DIST_DIR="dist_bin"
mkdir -p "$DIST_DIR"

echo "[*] Compiling 'ghostd' (Daemon)..."
pyinstaller --clean --onefile \
    --name ghostd \
    --distpath "$DIST_DIR" \
    --workpath "build/ghostd" \
    --specpath "build/spec" \
    src/ghosttunnel/daemon.py

echo "[*] Compiling 'ghostctl' (CLI)..."
pyinstaller --clean --onefile \
    --name ghostctl \
    --distpath "$DIST_DIR" \
    --workpath "build/ghostctl" \
    --specpath "build/spec" \
    src/ghosttunnel/cli/main.py

echo "[*] Compiling 'ghostgui' (GUI)..."
pyinstaller --clean --onefile \
    --name ghostgui \
    --windowed \
    --distpath "$DIST_DIR" \
    --workpath "build/ghostgui" \
    --specpath "build/spec" \
    src/ghosttunnel/gui/main.py

# Cleanup build artifacts
echo "[*] Cleaning up temporary build files..."
deactivate
rm -rf "$VENV_DIR"
rm -rf "build"

echo "[+] ========================================================="
echo "[+] Compilation successful!"
echo "[+] Binaries are located in the '${DIST_DIR}' directory:"
ls -lh "$DIST_DIR"
echo "[+]"
echo "[+] You can now run 'sudo ./install.sh' to install the native binaries."
echo "[+] ========================================================="
