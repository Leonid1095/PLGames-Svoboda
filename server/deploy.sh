#!/bin/bash
# Deploy / Update Svoboda API on VPS
# Usage:
#   First deploy:  bash deploy.sh
#   Update:        bash deploy.sh update
#   Clean old data: bash deploy.sh clean
set -e

ACTION="${1:-deploy}"
SERVICE_DIR="/opt/svoboda-api"
SERVICE_NAME="svoboda-api"

echo "=== Svoboda Analytics API — $ACTION ==="

if [ "$ACTION" = "update" ]; then
    echo "Updating api.py..."
    cp "$(dirname "$0")/api.py" "$SERVICE_DIR/api.py"
    systemctl restart "$SERVICE_NAME"
    echo "[OK] Restarted"
    systemctl status "$SERVICE_NAME" --no-pager -l | tail -5
    exit 0
fi

if [ "$ACTION" = "clean" ]; then
    echo "Removing old zapret v1 strategies from DB..."
    python3 - << 'PYEOF'
import sqlite3, json
from pathlib import Path
db = Path("/opt/svoboda-api/data/svoboda_server.db")
if not db.exists():
    print("DB not found")
    exit(0)
conn = sqlite3.connect(str(db))
cur = conn.cursor()
cur.execute("SELECT id, flags FROM strategy_scores")
rows = cur.fetchall()
removed = 0
for row_id, flags_json in rows:
    try:
        flags = json.loads(flags_json)
        if any(f.startswith("-") for f in flags):
            cur.execute("DELETE FROM strategy_scores WHERE id=?", (row_id,))
            removed += 1
    except Exception:
        pass
conn.commit()
conn.close()
print(f"Removed {removed} old-format strategies")
PYEOF
    exit 0
fi

# ── First deploy ──────────────────────────────────────────────────────────────
pip3 install fastapi "uvicorn[standard]" requests

mkdir -p "$SERVICE_DIR"
cp "$(dirname "$0")/api.py" "$(dirname "$0")/requirements.txt" "$SERVICE_DIR/"

# Generate random API key if not set
if [ -z "$SVOBODA_API_KEY" ]; then
    SVOBODA_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "Generated API key: $SVOBODA_API_KEY"
    echo "Add to client config.json: \"server_api_key\": \"$SVOBODA_API_KEY\""
fi

# Create systemd service
cat > "/etc/systemd/system/$SERVICE_NAME.service" << UNIT
[Unit]
Description=Svoboda Analytics API
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$SERVICE_DIR
Environment=SVOBODA_API_KEY=$SVOBODA_API_KEY
Environment=REGISTRATION_SECRET=$SVOBODA_API_KEY
ExecStart=/usr/bin/python3 -m uvicorn api:app --host 127.0.0.1 --port 8443
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo ""
echo "[OK] API running on 127.0.0.1:8443"
echo ""
echo "Next: nginx reverse proxy — add to your server config:"
echo '  location /api/ {'
echo '      proxy_pass http://127.0.0.1:8443;'
echo '  }'
echo ""
echo "To update after code changes:"
echo "  bash deploy.sh update"
echo ""
echo "To clean old zapret v1 data from DB:"
echo "  bash deploy.sh clean"
