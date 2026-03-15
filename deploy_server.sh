#!/bin/bash
# ============================================================================
#  PLGames Svoboda — Server Deploy Script
#  Deploys analytics API on Ubuntu VPS (alongside 3x-ui)
#
#  Usage:
#    sudo bash deploy_server.sh
#
#  What it does:
#    1. Installs Python3, nginx (if missing)
#    2. Creates /opt/svoboda-api with virtualenv
#    3. Deploys FastAPI app with systemd service
#    4. Configures nginx reverse proxy on /api/ path
#    5. Sets up API key + DonatePay key
# ============================================================================

set -euo pipefail

APP_DIR="/opt/svoboda-api"
APP_USER="svoboda"
SERVICE_NAME="svoboda-api"
API_PORT=8443

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "  ${RED}[ERROR]${NC} $1"; }
log_info() { echo -e "  ${CYAN}[i]${NC} $1"; }

echo ""
echo "  ===================================================="
echo "   PLGames Svoboda — Server Deploy"
echo "  ===================================================="
echo ""

# ─── Root check ──────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    log_err "Run as root: sudo bash deploy_server.sh"
    exit 1
fi

# ─── Detect 3x-ui ───────────────────────────────────────────────────────────

if systemctl is-active --quiet x-ui 2>/dev/null; then
    log_ok "3x-ui detected and running (will not be affected)"
fi

# ─── Step 1: System deps ────────────────────────────────────────────────────

echo ""
echo "  Step 1: System dependencies..."

apt-get update -qq 2>/dev/null

# Python
if ! command -v python3 &>/dev/null; then
    apt-get install -y -qq python3 python3-pip python3-venv
fi

PYTHON_BIN="python3"
PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log_ok "Python $PY_VER"

# nginx
if ! command -v nginx &>/dev/null; then
    apt-get install -y -qq nginx
    log_ok "nginx installed"
else
    log_ok "nginx found"
fi

# ─── Step 2: App setup ──────────────────────────────────────────────────────

echo ""
echo "  Step 2: Application setup..."

# User
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
    log_ok "Created user: $APP_USER"
fi

mkdir -p "$APP_DIR/data"

# ─── Step 3: Copy code ──────────────────────────────────────────────────────

echo ""
echo "  Step 3: Deploying code..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/server/api.py" ]; then
    cp "$SCRIPT_DIR/server/api.py" "$APP_DIR/api.py"
    cp "$SCRIPT_DIR/server/requirements.txt" "$APP_DIR/requirements.txt" 2>/dev/null || true
    log_ok "Copied from local project"
else
    if [ ! -f "$APP_DIR/api.py" ]; then
        log_err "api.py not found! Copy server/api.py to $APP_DIR/"
        exit 1
    fi
    log_ok "Using existing api.py"
fi

# Virtualenv
if [ ! -d "$APP_DIR/venv" ]; then
    "$PYTHON_BIN" -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet fastapi "uvicorn[standard]" requests
log_ok "Dependencies installed"

# ─── Step 4: Keys ───────────────────────────────────────────────────────────

echo ""
echo "  Step 4: API keys..."

# Generate API key
API_KEY_FILE="$APP_DIR/.api_key"
if [ ! -f "$API_KEY_FILE" ]; then
    API_KEY=$(openssl rand -hex 32)
    echo "$API_KEY" > "$API_KEY_FILE"
    chmod 600 "$API_KEY_FILE"
    log_ok "Generated API key"
else
    API_KEY=$(cat "$API_KEY_FILE")
    log_ok "Using existing API key"
fi

# DonatePay key
DONATE_KEY_FILE="$APP_DIR/.donatepay_key"
if [ ! -f "$DONATE_KEY_FILE" ]; then
    echo ""
    echo -e "  ${YELLOW}Enter your DonatePay API key (or press Enter to skip):${NC}"
    read -r DONATE_KEY
    if [ -n "$DONATE_KEY" ]; then
        echo "$DONATE_KEY" > "$DONATE_KEY_FILE"
        chmod 600 "$DONATE_KEY_FILE"
        log_ok "DonatePay key saved"
    else
        log_warn "DonatePay skipped (tier system won't work until configured)"
    fi
else
    log_ok "DonatePay key exists"
fi

# Environment file
cat > "$APP_DIR/.env" << EOF
SVOBODA_API_KEY=$API_KEY
SVOBODA_DB_PATH=$APP_DIR/data/svoboda_server.db
DONATEPAY_API_KEY=$(cat "$DONATE_KEY_FILE" 2>/dev/null || echo "")
EOF
chmod 600 "$APP_DIR/.env"

# Fix ownership
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
chmod 700 "$APP_DIR/data"

# ─── Step 5: Systemd ────────────────────────────────────────────────────────

echo ""
echo "  Step 5: Systemd service..."

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=PLGames Svoboda Analytics API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/uvicorn api:app --host 127.0.0.1 --port $API_PORT
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$APP_DIR/data
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
systemctl restart "$SERVICE_NAME"

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_ok "Service started"
else
    log_err "Service failed! Check: journalctl -u $SERVICE_NAME -n 30"
    journalctl -u "$SERVICE_NAME" -n 10 --no-pager
    exit 1
fi

# ─── Step 6: Nginx ──────────────────────────────────────────────────────────

echo ""
echo "  Step 6: Nginx..."

# Add API location to default site or create new one
NGINX_SNIPPET="/etc/nginx/conf.d/svoboda-api.conf"

cat > "$NGINX_SNIPPET" << NGINX
# PLGames Svoboda API — reverse proxy
# Works alongside any existing nginx config (3x-ui, etc)

server {
    listen 8080;
    server_name _;

    location /api/ {
        proxy_pass http://127.0.0.1:$API_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
    }
}
NGINX

if nginx -t 2>/dev/null; then
    systemctl reload nginx
    log_ok "Nginx configured on port 8080"
else
    log_err "Nginx config failed"
    rm -f "$NGINX_SNIPPET"
    log_warn "API accessible directly on 127.0.0.1:$API_PORT"
fi

# ─── Step 7: Firewall ───────────────────────────────────────────────────────

echo ""
echo "  Step 7: Firewall..."

if command -v ufw &>/dev/null; then
    ufw allow 8080/tcp 2>/dev/null && log_ok "Allowed port 8080"
else
    log_info "No ufw — make sure port 8080 is open"
fi

# ─── Step 8: Verify ─────────────────────────────────────────────────────────

echo ""
echo "  Step 8: Verification..."

HEALTH=$(curl -s --max-time 5 "http://127.0.0.1:${API_PORT}/api/v1/health" 2>/dev/null)
if echo "$HEALTH" | grep -q '"ok"'; then
    log_ok "Health check passed"
else
    log_warn "Health: $HEALTH"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

SERVER_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "  ===================================================="
echo "   DEPLOY COMPLETE"
echo "  ===================================================="
echo ""
echo "  API:        http://${SERVER_IP}:8080/api/v1/"
echo "  Health:     http://${SERVER_IP}:8080/api/v1/health"
echo "  Stats:      http://${SERVER_IP}:8080/api/v1/stats"
echo "  API Key:    $API_KEY"
echo ""
echo "  Service:    systemctl status $SERVICE_NAME"
echo "  Logs:       journalctl -u $SERVICE_NAME -f"
echo "  DB:         $APP_DIR/data/svoboda_server.db"
echo ""
echo "  ---- Put this in your client config.json ----"
echo ""
echo "  \"server_api_url\": \"http://${SERVER_IP}:8080\","
echo "  \"server_api_key\": \"$API_KEY\","
echo "  \"sync_enabled\": true"
echo ""
echo "  ---- Managing ----"
echo ""
echo "  Restart:    systemctl restart $SERVICE_NAME"
echo "  Stop:       systemctl stop $SERVICE_NAME"
echo "  Logs:       journalctl -u $SERVICE_NAME -f"
echo ""
echo "  DonatePay:  echo 'YOUR_KEY' > $APP_DIR/.donatepay_key"
echo "              Then update $APP_DIR/.env and restart"
echo ""
