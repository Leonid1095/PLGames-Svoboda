#!/bin/bash
# PLGames Svoboda — Linux installer
set -e

echo "=== PLGames Svoboda Installer ==="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: run as root (sudo ./install.sh)"
    exit 1
fi

# Check Python 3.10+
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo "Error: Python 3.10+ required"
    exit 1
fi

PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "Error: Python 3.10+ required (found $PY_VER)"
    exit 1
fi
echo "[OK] Python $PY_VER"

# Install Python dependencies
echo "Installing Python dependencies..."
$PYTHON -m pip install --quiet \
    scapy>=2.5.0 \
    requests>=2.31 \
    python-telegram-bot>=21.0 \
    schedule>=1.2 \
    psutil>=5.9

echo "[OK] Python dependencies installed"

# Download zapret2
ZAPRET_DIR="/opt/zapret2"
if [ ! -d "$ZAPRET_DIR" ]; then
    echo "Downloading zapret2..."
    git clone --depth 1 https://github.com/bol-van/zapret2.git "$ZAPRET_DIR"
    echo "[OK] zapret2 downloaded"
else
    echo "[OK] zapret2 already exists at $ZAPRET_DIR"
fi

# Build nfqws2
if [ ! -f "$ZAPRET_DIR/nfq/nfqws2" ]; then
    echo "Building nfqws2..."
    cd "$ZAPRET_DIR"
    make -C nfq || {
        echo "Warning: nfqws2 build failed. Install build dependencies:"
        echo "  apt install build-essential libnetfilter-queue-dev"
        echo "Then rebuild manually: cd $ZAPRET_DIR && make -C nfq"
    }
    cd - > /dev/null
fi

# Symlink binary
if [ -f "$ZAPRET_DIR/nfq/nfqws2" ]; then
    ln -sf "$ZAPRET_DIR/nfq/nfqws2" /usr/local/bin/nfqws2
    echo "[OK] nfqws2 linked to /usr/local/bin/nfqws2"
fi

# Install Svoboda as service
INSTALL_DIR="/opt/svoboda"
echo "Installing Svoboda to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r brain updater lua config.json "$INSTALL_DIR/"

# Create systemd service
cat > /etc/systemd/system/svoboda.service << 'UNIT'
[Unit]
Description=PLGames Svoboda - DPI Bypass Brain
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/svoboda
ExecStart=/usr/bin/python3 -m brain.svoboda_brain
Restart=on-failure
RestartSec=10
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable svoboda.service
echo "[OK] Systemd service installed"

echo ""
echo "=== Installation complete ==="
echo ""
echo "Commands:"
echo "  sudo systemctl start svoboda    # Start"
echo "  sudo systemctl stop svoboda     # Stop"
echo "  sudo systemctl status svoboda   # Status"
echo "  sudo journalctl -u svoboda -f   # Logs"
echo ""
echo "Config: $INSTALL_DIR/config.json"
echo "Strategy DB: $INSTALL_DIR/strategies_db.json"
echo "Logs: $INSTALL_DIR/svoboda.log"
