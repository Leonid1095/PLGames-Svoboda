#!/bin/bash
# Deploy Svoboda API on VPS (alongside 3x-ui)
set -e

echo "=== Deploying Svoboda Analytics API ==="

# Install Python deps
pip3 install fastapi uvicorn

# Create service directory
mkdir -p /opt/svoboda-api
cp api.py requirements.txt /opt/svoboda-api/

# Create systemd service (runs on port 8443)
cat > /etc/systemd/system/svoboda-api.service << 'UNIT'
[Unit]
Description=Svoboda Analytics API
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/svoboda-api
ExecStart=/usr/bin/python3 -m uvicorn api:app --host 127.0.0.1 --port 8443
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable svoboda-api
systemctl start svoboda-api

echo ""
echo "[OK] API running on 127.0.0.1:8443"
echo ""
echo "Next: configure nginx/caddy reverse proxy with HTTPS"
echo "Example nginx location block:"
echo '  location /api/ {'
echo '      proxy_pass http://127.0.0.1:8443;'
echo '  }'
