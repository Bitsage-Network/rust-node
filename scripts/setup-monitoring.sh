#!/usr/bin/env bash
# setup-monitoring.sh — Deploy Prometheus + Grafana via Docker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${BITSAGE_REPO_DIR:-$(dirname "$SCRIPT_DIR")}"
MONITORING_DIR="${REPO_DIR}/monitoring"
COORDINATOR_PORT="${BITSAGE_API_PORT:-8080}"
GRAFANA_PORT="${GRAFANA_PORT:-3001}"
PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"

echo "═══════════════════════════════════════════════════════════════"
echo "  BitSage Monitoring Stack Setup"
echo "  Prometheus: :${PROMETHEUS_PORT}  Grafana: :${GRAFANA_PORT}"
echo "═══════════════════════════════════════════════════════════════"

# --- Install Docker if needed ---
if ! command -v docker &>/dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER"
    echo "Docker installed. You may need to log out and back in for group changes."
fi

if ! docker compose version &>/dev/null && ! command -v docker-compose &>/dev/null; then
    echo "Installing docker-compose plugin..."
    sudo apt-get update && sudo apt-get install -y docker-compose-plugin
fi

# Determine compose command
if docker compose version &>/dev/null; then
    COMPOSE="docker compose"
else
    COMPOSE="docker-compose"
fi

# --- Create monitoring directory ---
mkdir -p "${MONITORING_DIR}"

# --- Copy Prometheus config ---
if [ -f "${REPO_DIR}/prometheus.yml" ]; then
    cp "${REPO_DIR}/prometheus.yml" "${MONITORING_DIR}/prometheus.yml"
else
    cat > "${MONITORING_DIR}/prometheus.yml" <<PROMEOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'bitsage-sepolia'
    environment: 'testnet'

rule_files:
  - 'alerts.yml'

scrape_configs:
  - job_name: 'bitsage-coordinator'
    static_configs:
      - targets: ['host.docker.internal:${COORDINATOR_PORT}']
    metrics_path: '/metrics'
    scrape_interval: 10s
PROMEOF
fi

# Patch prometheus.yml to use host.docker.internal
sed -i.bak "s|localhost:3000|host.docker.internal:${COORDINATOR_PORT}|g" "${MONITORING_DIR}/prometheus.yml" 2>/dev/null || true
sed -i.bak "s|localhost:${COORDINATOR_PORT}|host.docker.internal:${COORDINATOR_PORT}|g" "${MONITORING_DIR}/prometheus.yml" 2>/dev/null || true
rm -f "${MONITORING_DIR}/prometheus.yml.bak"

# --- Copy alerts ---
if [ -f "${REPO_DIR}/alerts.yml" ]; then
    cp "${REPO_DIR}/alerts.yml" "${MONITORING_DIR}/alerts.yml"
fi

# --- Create docker-compose file ---
cat > "${MONITORING_DIR}/docker-compose.yml" <<DCEOF
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: bitsage-prometheus
    restart: unless-stopped
    ports:
      - "${PROMETHEUS_PORT}:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./alerts.yml:/etc/prometheus/alerts.yml:ro
      - prometheus_data:/prometheus
    extra_hosts:
      - "host.docker.internal:host-gateway"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=30d'

  grafana:
    image: grafana/grafana:latest
    container_name: bitsage-grafana
    restart: unless-stopped
    ports:
      - "${GRAFANA_PORT}:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=\${GRAFANA_ADMIN_PASSWORD:-changeme}
      - GF_USERS_ALLOW_SIGN_UP=false
    depends_on:
      - prometheus

volumes:
  prometheus_data:
  grafana_data:
DCEOF

# --- Start stack ---
echo ""
echo "Starting monitoring stack..."
cd "${MONITORING_DIR}"
$COMPOSE up -d

# --- Open firewall ---
if command -v ufw &>/dev/null; then
    echo "Opening firewall ports..."
    sudo ufw allow "${PROMETHEUS_PORT}/tcp" 2>/dev/null || true
    sudo ufw allow "${GRAFANA_PORT}/tcp" 2>/dev/null || true
fi

# --- Verify ---
echo ""
echo "Waiting for services to start..."
sleep 5

PROM_OK=false
GRAF_OK=false

if curl -sf "http://localhost:${PROMETHEUS_PORT}/-/healthy" &>/dev/null; then
    PROM_OK=true
    echo "  Prometheus: OK (http://localhost:${PROMETHEUS_PORT})"
else
    echo "  Prometheus: NOT READY"
fi

if curl -sf "http://localhost:${GRAFANA_PORT}/api/health" &>/dev/null; then
    GRAF_OK=true
    echo "  Grafana:    OK (http://localhost:${GRAFANA_PORT}, admin/<GRAFANA_ADMIN_PASSWORD>)"
else
    echo "  Grafana:    NOT READY"
fi

# Check if prometheus is scraping
echo ""
echo "Checking Prometheus targets..."
TARGETS=$(curl -s "http://localhost:${PROMETHEUS_PORT}/api/v1/targets" 2>/dev/null)
if echo "$TARGETS" | grep -q '"health":"up"'; then
    echo "  Scraping: ACTIVE"
else
    echo "  Scraping: targets not yet up (coordinator may need /metrics endpoint)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
if $PROM_OK && $GRAF_OK; then
    echo "  Monitoring stack is RUNNING"
else
    echo "  Monitoring stack started (check logs: cd ${MONITORING_DIR} && $COMPOSE logs)"
fi
echo "═══════════════════════════════════════════════════════════════"
