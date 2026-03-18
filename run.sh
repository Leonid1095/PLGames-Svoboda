#!/bin/bash
# PLGames Svoboda — DPI Bypass Tool (Linux)
# Requires: root privileges, Python 3.10+, curl
#
# Usage: sudo ./run.sh

set -e
cd "$(dirname "$0")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e " ${GREEN}[OK]${NC} $1"; }
warn() { echo -e " ${YELLOW}[!]${NC} $1"; }
fail() { echo -e " ${RED}[ERROR]${NC} $1"; }

# ─── Language detection ──────────────────────────────────────
LANG_CODE="${LANG:-en_US}"
if [[ "$LANG_CODE" == ru_* ]] || [[ "$LANG_CODE" == ru.* ]]; then
    IS_RU=1
else
    IS_RU=0
fi

echo ""
echo " ===================================================="
if [ "$IS_RU" -eq 1 ]; then
    echo "  PLGames Svoboda — Обход блокировок (Linux)"
else
    echo "  PLGames Svoboda — DPI Bypass Tool (Linux)"
fi
echo " ===================================================="
echo ""

# ─── Root check ──────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    if [ "$IS_RU" -eq 1 ]; then
        warn "Требуются права root для nfqws2/iptables"
        echo "  Запустите: sudo $0"
    else
        warn "Root privileges required for nfqws2/iptables"
        echo "  Run: sudo $0"
    fi
    exit 1
fi
ok "Root privileges"

# ─── Python check ────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    fail "Python 3 not found!"
    if [ "$IS_RU" -eq 1 ]; then
        echo "  Установите: sudo apt install python3 python3-pip"
    else
        echo "  Install: sudo apt install python3 python3-pip"
    fi
    exit 1
fi
PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
ok "Python $PY_VER"

# ─── Dependencies ────────────────────────────────────────────
if ! python3 -c "import requests" 2>/dev/null; then
    if [ "$IS_RU" -eq 1 ]; then
        echo "  Установка зависимостей..."
    else
        echo "  Installing dependencies..."
    fi
    pip3 install --quiet -r requirements.txt 2>/dev/null || python3 -m pip install --quiet -r requirements.txt
fi
ok "Dependencies"

# ─── Self-update from git ────────────────────────────────────
if [ -d ".git" ]; then
    if [ "$IS_RU" -eq 1 ]; then
        echo -n "  Проверка обновлений..."
    else
        echo -n "  Checking for updates..."
    fi

    git fetch origin main --quiet 2>/dev/null || true
    LOCAL=$(git rev-parse HEAD 2>/dev/null)
    REMOTE=$(git rev-parse origin/main 2>/dev/null || echo "$LOCAL")

    if [ "$LOCAL" != "$REMOTE" ]; then
        echo ""
        if [ "$IS_RU" -eq 1 ]; then
            echo "  Обновление Svoboda..."
        else
            echo "  Updating Svoboda..."
        fi
        git pull origin main --quiet 2>/dev/null
        ok "Updated"
    else
        echo ""
        ok "Up to date"
    fi
fi

# ─── zapret2 check / download ────────────────────────────────
ZAPRET_BIN=""
for d in zapret2-*/binaries/linux-x86_64/nfqws2; do
    if [ -x "$d" ]; then
        ZAPRET_BIN="$d"
        break
    fi
done

if [ -z "$ZAPRET_BIN" ]; then
    # Try to find in system
    if command -v nfqws2 &>/dev/null; then
        ZAPRET_BIN=$(which nfqws2)
    fi
fi

if [ -z "$ZAPRET_BIN" ]; then
    if [ "$IS_RU" -eq 1 ]; then
        echo "  Скачивание zapret2..."
    else
        echo "  Downloading zapret2..."
    fi

    # Get latest release
    LATEST=$(curl -sL "https://api.github.com/repos/bol-van/zapret2/releases/latest" | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null || echo "v0.9.4.5")
    ARCHIVE="zapret2-${LATEST}-linux-x86_64.tar.gz"
    DOWNLOAD_URL="https://github.com/bol-van/zapret2/releases/download/${LATEST}/${ARCHIVE}"

    curl -sL "$DOWNLOAD_URL" -o "/tmp/$ARCHIVE" 2>/dev/null
    if [ -f "/tmp/$ARCHIVE" ]; then
        tar -xzf "/tmp/$ARCHIVE" 2>/dev/null || true
        rm -f "/tmp/$ARCHIVE"
    fi

    # Search again
    for d in zapret2-*/binaries/linux-x86_64/nfqws2; do
        if [ -x "$d" ]; then
            ZAPRET_BIN="$d"
            break
        fi
    done
fi

if [ -z "$ZAPRET_BIN" ] || [ ! -x "$ZAPRET_BIN" ]; then
    fail "nfqws2 binary not found"
    if [ "$IS_RU" -eq 1 ]; then
        echo "  Скачайте: https://github.com/bol-van/zapret2/releases"
    else
        echo "  Download: https://github.com/bol-van/zapret2/releases"
    fi
    exit 1
fi
ok "nfqws2: $ZAPRET_BIN"

# ─── Check Lua libs ──────────────────────────────────────────
LUA_DIR=""
for d in zapret2-*/lua/zapret-lib.lua; do
    LUA_DIR="$(dirname "$d")"
    break
done

if [ -z "$LUA_DIR" ]; then
    fail "zapret2 Lua libs not found"
    exit 1
fi
ok "Lua libs: $LUA_DIR"

# ─── Kill leftover nfqws2 ────────────────────────────────────
killall nfqws2 2>/dev/null || true

# ─── Setup iptables for NFQUEUE ──────────────────────────────
setup_iptables() {
    # Clean up old rules
    iptables -t mangle -D POSTROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass 2>/dev/null || true
    iptables -t mangle -D POSTROUTING -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass 2>/dev/null || true
    iptables -t mangle -D POSTROUTING -p udp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass 2>/dev/null || true

    # Add rules
    iptables -t mangle -A POSTROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass
    iptables -t mangle -A POSTROUTING -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass
    iptables -t mangle -A POSTROUTING -p udp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass

    ok "iptables NFQUEUE rules added"
}

cleanup_iptables() {
    iptables -t mangle -D POSTROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass 2>/dev/null || true
    iptables -t mangle -D POSTROUTING -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass 2>/dev/null || true
    iptables -t mangle -D POSTROUTING -p udp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass 2>/dev/null || true
    killall nfqws2 2>/dev/null || true
}

# Cleanup on exit
trap cleanup_iptables EXIT INT TERM

# ─── Mode selection ──────────────────────────────────────────
echo ""
if [ "$IS_RU" -eq 1 ]; then
    echo " [1] Консольный режим (полный вывод)"
    echo " [2] Фоновый режим (systemd сервис)"
    echo ""
    read -p " Выберите [1/2]: " MODE
else
    echo " [1] Console mode (full output)"
    echo " [2] Background mode (systemd service)"
    echo ""
    read -p " Choose [1/2]: " MODE
fi

if [ "$MODE" == "2" ]; then
    # Install systemd service
    cat > /etc/systemd/system/svoboda.service <<SVCEOF
[Unit]
Description=PLGames Svoboda DPI Bypass
After=network.target

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStartPre=/sbin/iptables -t mangle -A POSTROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass
ExecStartPre=/sbin/iptables -t mangle -A POSTROUTING -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass
ExecStartPre=/sbin/iptables -t mangle -A POSTROUTING -p udp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass
ExecStart=$(which python3) $(pwd)/run_real.py
ExecStopPost=/sbin/iptables -t mangle -D POSTROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass
ExecStopPost=/sbin/iptables -t mangle -D POSTROUTING -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass
ExecStopPost=/sbin/iptables -t mangle -D POSTROUTING -p udp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable svoboda
    systemctl start svoboda

    ok "Systemd service installed and started"
    if [ "$IS_RU" -eq 1 ]; then
        echo "  Статус: systemctl status svoboda"
        echo "  Логи:   journalctl -u svoboda -f"
        echo "  Стоп:   systemctl stop svoboda"
    else
        echo "  Status: systemctl status svoboda"
        echo "  Logs:   journalctl -u svoboda -f"
        echo "  Stop:   systemctl stop svoboda"
    fi
    exit 0
fi

# ─── Console mode ────────────────────────────────────────────
setup_iptables

# Export for Python
export SVOBODA_NFQUEUE=200
export SVOBODA_ZAPRET_BIN="$ZAPRET_BIN"
export SVOBODA_LUA_DIR="$LUA_DIR"

python3 run_real.py
