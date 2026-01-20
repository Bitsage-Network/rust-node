# 📊 Prometheus Metrics for SageGuard Consensus

**Date:** 2026-01-02
**Status:** ✅ Complete

---

## Overview

This document describes the Prometheus metrics implementation for monitoring the SageGuard BFT consensus system. Comprehensive metrics are exposed for validator activity, voting rounds, fraud detection, and system health.

## Quick Start

### 1. Start the Coordinator with Metrics Enabled

```rust
use axum::Router;
use bitsage_node::api::metrics_routes;

#[tokio::main]
async fn main() {
    // Create main app router
    let app = Router::new()
        .merge(metrics_routes())  // Add /metrics and /health endpoints
        // ... other routes ...
        ;

    // Start server
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

### 2. Verify Metrics Endpoint

```bash
# Check metrics are being exposed
curl http://localhost:3000/metrics

# Check health endpoint
curl http://localhost:3000/health
```

### 3. Run Prometheus

```bash
# Using Docker
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  -v $(pwd)/alerts.yml:/etc/prometheus/alerts.yml \
  prom/prometheus

# Or using docker-compose (see below)
docker-compose up -d prometheus grafana
```

### 4. Access Dashboards

- **Prometheus UI:** http://localhost:9090
- **Grafana:** http://localhost:3001 (admin/admin)

---

## Metrics Exposed

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| `consensus_votes_total` | `validator`, `job_id` | Total votes submitted |
| `consensus_rounds_total` | `outcome` | Total consensus rounds (approved/rejected/timeout/inconclusive) |
| `consensus_fraud_detected_total` | `job_id` | Total fraud cases detected |
| `consensus_validators_registered_total` | `validator` | Total validators registered |
| `consensus_validators_removed_total` | `validator`, `reason` | Total validators removed |
| `consensus_view_changes_total` | `reason` | Total view changes (leader rotation) |
| `consensus_persistence_operations_total` | `operation`, `status` | Persistence operations |

### Gauges

| Metric | Description |
|--------|-------------|
| `consensus_active_validators` | Current number of active validators |
| `consensus_pending_votes{job_id}` | Current pending votes for a job |
| `consensus_current_view` | Current view number (leader election) |

### Histograms

| Metric | Labels | Buckets | Description |
|--------|--------|---------|-------------|
| `consensus_vote_duration_seconds` | `job_id` | 0.1, 0.5, 1, 2, 5, 10, 30, 60 | Vote collection duration |
| `consensus_finalization_duration_seconds` | `outcome` | 0.01, 0.05, 0.1, 0.5, 1, 2, 5 | Finalization duration |
| `consensus_persistence_duration_seconds` | `operation` | 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1 | Persistence operation duration |

---

## Example Queries

### Validator Health

```promql
# Active validators over time
consensus_active_validators

# Validator registration rate
rate(consensus_validators_registered_total[5m])

# Validators removed in last hour
increase(consensus_validators_removed_total[1h])
```

### Consensus Performance

```promql
# Consensus approval rate
rate(consensus_rounds_total{outcome="approved"}[5m]) /
rate(consensus_rounds_total[5m])

# Timeout rate
rate(consensus_rounds_total{outcome="timeout"}[5m])

# Average finalization time (95th percentile)
histogram_quantile(0.95,
  rate(consensus_finalization_duration_seconds_bucket[5m])
)

# Vote collection latency by percentile
histogram_quantile(0.50, rate(consensus_vote_duration_seconds_bucket[5m]))  # p50
histogram_quantile(0.95, rate(consensus_vote_duration_seconds_bucket[5m]))  # p95
histogram_quantile(0.99, rate(consensus_vote_duration_seconds_bucket[5m]))  # p99
```

### Fraud Detection

```promql
# Fraud detection rate
rate(consensus_fraud_detected_total[5m])

# Total fraud cases in last 24 hours
increase(consensus_fraud_detected_total[24h])

# Fraud detection by job
topk(10, sum by (job_id) (increase(consensus_fraud_detected_total[1h])))
```

### Leader Election

```promql
# View changes per hour
rate(consensus_view_changes_total[1h]) * 3600

# Current view number
consensus_current_view

# View change reasons
sum by (reason) (rate(consensus_view_changes_total[5m]))
```

### Persistence

```promql
# Persistence operation success rate
rate(consensus_persistence_operations_total{status="success"}[5m]) /
rate(consensus_persistence_operations_total[5m])

# Persistence latency (95th percentile)
histogram_quantile(0.95,
  rate(consensus_persistence_duration_seconds_bucket[5m])
)
```

---

## Docker Compose Setup

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./alerts.yml:/etc/prometheus/alerts.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3001:3000"  # Use 3001 to avoid conflict with coordinator
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    depends_on:
      - prometheus
    restart: unless-stopped

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager-data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    restart: unless-stopped

volumes:
  prometheus-data:
  grafana-data:
  alertmanager-data:
```

Start the stack:

```bash
docker-compose up -d
```

---

## Grafana Dashboard

### Import Pre-built Dashboard

1. Go to Grafana: http://localhost:3001
2. Login (admin/admin)
3. Go to Dashboards → Import
4. Upload `grafana/dashboards/consensus_dashboard.json`

### Dashboard Panels

**Validator Overview:**
- Active Validators (gauge)
- Validator Registration Rate (graph)
- Validators Removed (counter)

**Consensus Performance:**
- Consensus Rounds by Outcome (pie chart)
- Approval Rate Over Time (graph)
- Timeout Rate (graph)
- Finalization Latency p95/p99 (graph)

**Fraud Detection:**
- Fraud Detection Rate (graph)
- Total Fraud Cases (counter)
- Fraud by Job ID (table)

**Leader Election:**
- Current View Number (gauge)
- View Changes Over Time (graph)
- View Change Reasons (bar chart)

**System Health:**
- Persistence Success Rate (graph)
- Persistence Latency (histogram)
- Pending Votes (heatmap)

---

## Alerting

### Configure Alertmanager

Create `alertmanager.yml`:

```yaml
global:
  resolve_timeout: 5m
  slack_api_url: 'YOUR_SLACK_WEBHOOK_URL'

route:
  group_by: ['alertname', 'cluster']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'slack-notifications'

  routes:
    - match:
        severity: critical
      receiver: 'slack-critical'
      continue: true

receivers:
  - name: 'slack-notifications'
    slack_configs:
      - channel: '#bitsage-alerts'
        title: 'BitSage Alert'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

  - name: 'slack-critical'
    slack_configs:
      - channel: '#bitsage-critical'
        title: 'CRITICAL: BitSage Alert'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
        send_resolved: true
```

### Alert Rules

See `alerts.yml` for comprehensive alerting rules including:
- Low validator count
- High fraud detection rate
- Slow consensus finalization
- High timeout rates
- Persistence failures

---

## Production Best Practices

### 1. Metrics Retention

```yaml
# prometheus.yml
global:
  retention.time: 30d  # Keep 30 days of metrics
  retention.size: 50GB  # Or max 50GB
```

### 2. High Availability

Run multiple Prometheus instances with remote write to a central time-series database:

```yaml
remote_write:
  - url: https://your-victoria-metrics.com/api/v1/write
    basic_auth:
      username: 'metrics'
      password: 'your-password'
```

### 3. Resource Limits

```yaml
# docker-compose.yml
services:
  prometheus:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

### 4. Security

```yaml
# Protect metrics endpoint
# In your coordinator:
use tower_http::auth::RequireAuthorizationLayer;

let app = Router::new()
    .route("/metrics", get(metrics_handler))
    .layer(RequireAuthorizationLayer::bearer("your-secret-token"));
```

### 5. Rate Limiting

```rust
// Add rate limiting to metrics endpoint
use tower::limit::RateLimitLayer;
use std::time::Duration;

let app = Router::new()
    .route("/metrics", get(metrics_handler))
    .layer(RateLimitLayer::new(10, Duration::from_secs(1)));
```

---

## Monitoring Checklist

### Daily
- [ ] Check validator count
- [ ] Review fraud detection alerts
- [ ] Monitor consensus approval rate
- [ ] Check for timeout spikes

### Weekly
- [ ] Review finalization latency trends
- [ ] Analyze view change frequency
- [ ] Check persistence operation health
- [ ] Review disk usage for Prometheus data

### Monthly
- [ ] Optimize alerting rules based on false positives
- [ ] Review dashboard effectiveness
- [ ] Update retention policies if needed
- [ ] Audit metrics cardinality

---

## Troubleshooting

### Metrics Not Appearing

```bash
# Check if endpoint is accessible
curl http://localhost:3000/metrics

# Check Prometheus targets
# Go to: http://localhost:9090/targets

# Check Prometheus logs
docker logs prometheus
```

### High Cardinality Issues

```promql
# Find metrics with high cardinality
topk(10, count by (__name__)({__name__=~".+"}))

# Check label cardinality
topk(10, count by (validator)(consensus_votes_total))
```

### Slow Queries

```promql
# Enable query logging in prometheus.yml
global:
  query_log_file: /prometheus/query.log

# Analyze slow queries
grep "slow_query" /prometheus/query.log
```

---

## Example Integration

```rust
use axum::{Router, Server};
use bitsage_node::api::metrics_routes;
use bitsage_node::coordinator::consensus_init::{initialize_consensus, ConsensusInitConfig};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize consensus
    let config = ConsensusInitConfig::from_env()?;
    let consensus = initialize_consensus(config).await?;

    // Create API with metrics
    let app = Router::new()
        .merge(metrics_routes())  // /metrics and /health
        // ... other routes ...
        ;

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Metrics available at http://localhost:3000/metrics");

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
```

---

## Resources

- **Prometheus Documentation:** https://prometheus.io/docs/
- **Grafana Documentation:** https://grafana.com/docs/
- **PromQL Guide:** https://prometheus.io/docs/prometheus/latest/querying/basics/
- **Best Practices:** https://prometheus.io/docs/practices/

---

## Summary

✅ **Implemented:**
- Comprehensive consensus metrics
- Prometheus endpoint at `/metrics`
- Health check at `/health`
- Alert rules for critical events
- Docker Compose setup
- Grafana dashboard examples

✅ **Metrics Coverage:**
- Validator activity (registration, removal, active count)
- Consensus rounds (approved, rejected, timeout, inconclusive)
- Fraud detection
- View changes (leader rotation)
- Persistence operations
- Performance histograms

🎯 **Production Ready:** Monitoring system is fully operational and ready for production deployment.

*Last Updated: 2026-01-02*
