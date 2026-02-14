#!/bin/bash
# =============================================================================
# BitSage — Nginx Reverse Proxy Setup
# =============================================================================
# Exposes coordinator API externally via nginx with optional SSL.
#
# Usage:
#   ./scripts/setup-nginx.sh
#   BITSAGE_DOMAIN=node.bitsage.network ./scripts/setup-nginx.sh
#   BITSAGE_SSL=none ./scripts/setup-nginx.sh   # HTTP only
# =============================================================================

set -euo pipefail

DOMAIN="${BITSAGE_DOMAIN:-}"
SSL_MODE="${BITSAGE_SSL:-self-signed}"  # letsencrypt | self-signed | none
COORDINATOR_PORT="${BITSAGE_COORDINATOR_PORT:-8080}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }

SERVER_NAME="${DOMAIN:-_}"
if [ -z "$DOMAIN" ]; then
    SERVER_IP=$(curl -s4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    SSL_MODE="${BITSAGE_SSL:-self-signed}"
    log_info "No domain set — using IP $SERVER_IP"
fi

echo ""
echo "================================================================="
echo "  BitSage — Nginx Reverse Proxy Setup"
echo "  Domain: ${DOMAIN:-<server-ip>} | SSL: $SSL_MODE"
echo "================================================================="
echo ""

# ── Step 1: Install nginx ──────────────────────────────────────────────────
log_step "Step 1/5: Installing nginx"

if ! command -v nginx &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq nginx >/dev/null 2>&1
fi
log_success "nginx installed"

# ── Step 2: SSL Certificates ───────────────────────────────────────────────
log_step "Step 2/5: SSL certificates"

CERT_PATH="/etc/ssl/bitsage"
sudo mkdir -p "$CERT_PATH"

case "$SSL_MODE" in
    letsencrypt)
        if [ -z "$DOMAIN" ]; then
            log_warn "Let's Encrypt requires a domain — falling back to self-signed"
            SSL_MODE="self-signed"
        else
            if ! command -v certbot &>/dev/null; then
                sudo apt-get install -y -qq certbot python3-certbot-nginx >/dev/null 2>&1
            fi
            sudo certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos \
                --register-unsafely-without-email 2>/dev/null || true
            SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            log_success "Let's Encrypt cert obtained for $DOMAIN"
        fi
        ;;
    none)
        log_info "SSL disabled — HTTP only"
        ;;
esac

# Self-signed fallback
if [ "$SSL_MODE" = "self-signed" ]; then
    SSL_CERT="$CERT_PATH/cert.pem"
    SSL_KEY="$CERT_PATH/key.pem"
    if [ ! -f "$SSL_CERT" ]; then
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SSL_KEY" -out "$SSL_CERT" \
            -subj "/CN=${DOMAIN:-bitsage-node}" 2>/dev/null
        log_success "Self-signed certificate generated"
    else
        log_info "Self-signed certificate already exists"
    fi
fi

# ── Step 3: Nginx Config ───────────────────────────────────────────────────
log_step "Step 3/5: Configuring nginx"

if [ "$SSL_MODE" = "none" ]; then
    # HTTP-only config
    sudo tee /etc/nginx/sites-available/bitsage >/dev/null <<EOF
server {
    listen 80;
    server_name ${SERVER_NAME};

    location / {
        proxy_pass http://127.0.0.1:${COORDINATOR_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:${COORDINATOR_PORT}/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
    }
}
EOF
else
    # HTTPS + redirect config
    sudo tee /etc/nginx/sites-available/bitsage >/dev/null <<EOF
server {
    listen 80;
    server_name ${SERVER_NAME};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${SERVER_NAME};

    ssl_certificate     ${SSL_CERT};
    ssl_certificate_key ${SSL_KEY};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:${COORDINATOR_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:${COORDINATOR_PORT}/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
    }
}
EOF
fi

sudo ln -sf /etc/nginx/sites-available/bitsage /etc/nginx/sites-enabled/bitsage
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t 2>/dev/null
log_success "Nginx configured"

# ── Step 4: Firewall ───────────────────────────────────────────────────────
log_step "Step 4/5: Opening firewall ports"

if command -v ufw &>/dev/null; then
    sudo ufw allow 80/tcp  >/dev/null 2>&1 || true
    sudo ufw allow 443/tcp >/dev/null 2>&1 || true
    log_success "UFW: ports 80, 443 open"
else
    log_info "UFW not found — ensure ports 80/443 are open"
fi

# ── Step 5: Start & Verify ─────────────────────────────────────────────────
log_step "Step 5/5: Starting nginx"

sudo systemctl enable nginx >/dev/null 2>&1
sudo systemctl restart nginx

sleep 2

if [ "$SSL_MODE" = "none" ]; then
    ENDPOINT="http://${DOMAIN:-${SERVER_IP:-localhost}}"
else
    ENDPOINT="https://${DOMAIN:-${SERVER_IP:-localhost}}"
fi

if curl -sfk "$ENDPOINT/api/health" >/dev/null 2>&1; then
    log_success "Nginx is proxying to coordinator"
else
    log_warn "Could not verify proxy — check: nginx -t && journalctl -u nginx -f"
fi

echo ""
echo "================================================================="
echo "  Nginx Setup Complete"
echo "  Endpoint: $ENDPOINT"
echo "  SSL:      $SSL_MODE"
echo ""
echo "  API:       $ENDPOINT/api/health"
echo "  WebSocket: ${ENDPOINT/http/ws}/ws"
echo ""
echo "  Test:"
echo "    curl -k $ENDPOINT/api/health"
echo "    curl -k $ENDPOINT/api/workers/list"
echo "================================================================="
