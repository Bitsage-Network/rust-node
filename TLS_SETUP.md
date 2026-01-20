# TLS/HTTPS Certificate Management

**Date:** 2026-01-02
**Status:** ✅ Production Ready
**Security:** HTTPS enforced for all production deployments

---

## Overview

The BitSage coordinator now includes comprehensive TLS/HTTPS support with:
- ✅ Production certificate loading (Let's Encrypt, custom CAs)
- ✅ Self-signed certificates for development/testing
- ✅ Automatic certificate validation and expiry checking
- ✅ HTTP to HTTPS redirect middleware
- ✅ Certificate rotation support
- ✅ Modern TLS 1.3 with secure cipher suites

---

## Quick Start

### Development (Self-Signed Certificate)

```rust
use bitsage_node::security::tls::{TlsConfig, load_tls_config};
use axum::Router;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<()> {
    // Generate self-signed certificate
    let tls_config = TlsConfig::self_signed("localhost")?;
    let server_config = load_tls_config(tls_config).await?;

    // Create Axum app
    let app = Router::new()
        .route("/", get(|| async { "Hello HTTPS!" }));

    // Start HTTPS server
    let addr = "0.0.0.0:3443".parse()?;

    axum_server::bind_rustls(addr, server_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
```

### Production (Let's Encrypt)

```rust
use bitsage_node::security::tls::{TlsConfig, load_tls_config};
use bitsage_node::security::https_redirect_middleware;
use axum::{Router, middleware};

#[tokio::main]
async fn main() -> Result<()> {
    // Load Let's Encrypt certificates
    let tls_config = TlsConfig::from_pem_files(
        "/etc/letsencrypt/live/coordinator.bitsage.network/fullchain.pem",
        "/etc/letsencrypt/live/coordinator.bitsage.network/privkey.pem"
    )?;

    let server_config = load_tls_config(tls_config).await?;

    // Main HTTPS app
    let https_app = Router::new()
        .route("/api/jobs", post(submit_job))
        .route("/health", get(health_check));

    // HTTP redirect server (port 80)
    let http_app = Router::new()
        .layer(middleware::from_fn(https_redirect_middleware));

    // Start both servers
    tokio::spawn(async move {
        axum_server::bind("0.0.0.0:80".parse().unwrap())
            .serve(http_app.into_make_service())
            .await
            .unwrap();
    });

    // HTTPS server (port 443)
    axum_server::bind_rustls("0.0.0.0:443".parse()?, server_config)
        .serve(https_app.into_make_service())
        .await?;

    Ok(())
}
```

---

## Certificate Acquisition

### Option 1: Let's Encrypt (Recommended for Production)

Let's Encrypt provides free, automated SSL/TLS certificates with 90-day validity.

#### Using Certbot

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Obtain certificate (HTTP-01 challenge)
sudo certbot certonly --standalone \
  -d coordinator.bitsage.network \
  -d api.bitsage.network \
  --email admin@bitsage.network \
  --agree-tos

# Certificates will be saved to:
# /etc/letsencrypt/live/coordinator.bitsage.network/fullchain.pem
# /etc/letsencrypt/live/coordinator.bitsage.network/privkey.pem
```

#### Automatic Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Add to crontab for automatic renewal
sudo crontab -e

# Add line (runs twice daily):
0 */12 * * * certbot renew --quiet --deploy-hook "systemctl reload bitsage-coordinator"
```

### Option 2: Custom CA Certificate

For enterprise deployments with internal Certificate Authorities:

```bash
# Generate private key
openssl genrsa -out coordinator.key 2048

# Generate certificate signing request (CSR)
openssl req -new -key coordinator.key -out coordinator.csr \
  -subj "/CN=coordinator.bitsage.network/O=BitSage Network/C=US"

# Sign with your CA
openssl x509 -req -in coordinator.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out coordinator.crt -days 365

# Use in coordinator
let tls_config = TlsConfig::from_pem_files(
    "coordinator.crt",
    "coordinator.key"
)?;
```

### Option 3: Self-Signed (Development Only)

The coordinator can generate self-signed certificates automatically:

```rust
let tls_config = TlsConfig::self_signed("localhost")?;
```

**⚠️ Warning:** Self-signed certificates are **NOT suitable for production**. They will cause browser warnings and are vulnerable to MITM attacks.

---

## Configuration

### Environment Variables

```bash
# TLS Mode: "disabled", "file", "self-signed"
export TLS_MODE=file

# Certificate paths (for file mode)
export TLS_CERT_PATH=/etc/letsencrypt/live/coordinator.bitsage.network/fullchain.pem
export TLS_KEY_PATH=/etc/letsencrypt/live/coordinator.bitsage.network/privkey.pem

# HTTP to HTTPS redirect
export TLS_ENABLE_REDIRECT=true

# Ports
export HTTP_PORT=80
export HTTPS_PORT=443

# Certificate expiry warning (days)
export TLS_EXPIRY_WARNING_DAYS=30

# Auto-reload certificates on file changes
export TLS_AUTO_RELOAD=true
```

### Configuration File (config/coordinator.toml)

```toml
[tls]
mode = "file"
enable_redirect = true
http_port = 80
https_port = 443
expiry_warning_days = 30
auto_reload = true

[tls.file]
cert_path = "/etc/letsencrypt/live/coordinator.bitsage.network/fullchain.pem"
key_path = "/etc/letsencrypt/live/coordinator.bitsage.network/privkey.pem"
```

### From Code

```rust
use bitsage_node::security::tls::{TlsConfig, TlsMode};

// From environment
let config = TlsConfig::from_env()?;

// From files
let config = TlsConfig::from_pem_files(
    "/path/to/fullchain.pem",
    "/path/to/privkey.pem"
)?;

// Self-signed
let config = TlsConfig::self_signed("localhost")?;

// Custom configuration
let config = TlsConfig {
    mode: TlsMode::File {
        cert_path: "/etc/ssl/coordinator.crt".into(),
        key_path: "/etc/ssl/coordinator.key".into(),
    },
    enable_redirect: true,
    http_port: 8080,  // Custom HTTP port
    https_port: 8443, // Custom HTTPS port
    expiry_warning_days: 14,
    auto_reload: true,
};
```

---

## Certificate Validation

The TLS module automatically validates certificates on load:

```rust
use bitsage_node::security::tls::{load_certificates, check_certificate_expiry};

// Load and validate
let certs = load_certificates(Path::new("/path/to/cert.pem"))?;

// Check expiry (warns if < 30 days remaining)
check_certificate_expiry(&certs, 30)?;

// Get certificate info
let info = get_certificate_info(&certs)?;
println!("{}", info);
```

**Output:**
```
Certificate 0:
  Subject: CN=coordinator.bitsage.network
  Issuer: CN=Let's Encrypt Authority X3
  Serial: 3a4b5c6d7e8f9a0b
  Valid from: Fri, 01 Jan 2026 00:00:00 +0000
  Valid until: Thu, 01 Apr 2026 00:00:00 +0000
  Subject Alternative Names:
    - DNSName("coordinator.bitsage.network")
    - DNSName("api.bitsage.network")
```

---

## HTTP to HTTPS Redirect

### Basic Redirect

Redirect all HTTP traffic to HTTPS:

```rust
use bitsage_node::security::https_redirect_middleware;
use axum::{Router, middleware};

let http_app = Router::new()
    .layer(middleware::from_fn(https_redirect_middleware));

// All requests to http://example.com/path
// redirect to https://example.com/path
```

### With Health Check Exception

Allow health checks on HTTP (for load balancers):

```rust
use bitsage_node::security::https_redirect_with_health_exception;

let http_app = Router::new()
    .route("/health", get(health_check))
    .layer(middleware::from_fn(https_redirect_with_health_exception));

// /health works on HTTP
// All other routes redirect to HTTPS
```

### Custom HTTPS Port

For non-standard ports:

```rust
use bitsage_node::security::https_redirect_to_port;

let redirect = https_redirect_to_port(8443);
let http_app = Router::new()
    .layer(middleware::from_fn(redirect));

// Redirects to https://example.com:8443/path
```

---

## Production Deployment

### Docker Deployment

**Dockerfile:**
```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/coordinator /usr/local/bin/

# Create certificate directory
RUN mkdir -p /etc/bitsage/certs

EXPOSE 80 443

ENTRYPOINT ["coordinator"]
```

**Docker Compose with Let's Encrypt:**
```yaml
version: '3.8'

services:
  coordinator:
    build: .
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - coordinator-data:/var/lib/bitsage
    environment:
      - TLS_MODE=file
      - TLS_CERT_PATH=/etc/letsencrypt/live/coordinator.bitsage.network/fullchain.pem
      - TLS_KEY_PATH=/etc/letsencrypt/live/coordinator.bitsage.network/privkey.pem
      - TLS_ENABLE_REDIRECT=true
    restart: unless-stopped

volumes:
  coordinator-data:
```

### Kubernetes Deployment

**Ingress with cert-manager:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bitsage-coordinator
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    kubernetes.io/tls-acme: "true"
spec:
  tls:
  - hosts:
    - coordinator.bitsage.network
    secretName: coordinator-tls
  rules:
  - host: coordinator.bitsage.network
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: coordinator
            port:
              number: 443
```

**Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bitsage-coordinator
spec:
  replicas: 3
  selector:
    matchLabels:
      app: coordinator
  template:
    metadata:
      labels:
        app: coordinator
    spec:
      containers:
      - name: coordinator
        image: bitsage/coordinator:latest
        ports:
        - containerPort: 443
          name: https
        - containerPort: 80
          name: http
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/bitsage/certs
          readOnly: true
        env:
        - name: TLS_MODE
          value: "file"
        - name: TLS_CERT_PATH
          value: "/etc/bitsage/certs/tls.crt"
        - name: TLS_KEY_PATH
          value: "/etc/bitsage/certs/tls.key"
      volumes:
      - name: tls-certs
        secret:
          secretName: coordinator-tls
```

### Systemd Service

**/etc/systemd/system/bitsage-coordinator.service:**
```ini
[Unit]
Description=BitSage Coordinator
After=network.target

[Service]
Type=simple
User=bitsage
WorkingDirectory=/opt/bitsage
ExecStart=/usr/local/bin/coordinator
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Environment
Environment="TLS_MODE=file"
Environment="TLS_CERT_PATH=/etc/letsencrypt/live/coordinator.bitsage.network/fullchain.pem"
Environment="TLS_KEY_PATH=/etc/letsencrypt/live/coordinator.bitsage.network/privkey.pem"
Environment="TLS_ENABLE_REDIRECT=true"

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/bitsage

[Install]
WantedBy=multi-user.target
```

---

## Certificate Rotation

### Automatic Reload

The coordinator can automatically reload certificates when files change:

```rust
use bitsage_node::security::tls::{TlsConfig, load_tls_config, watch_certificate_files};

let config = TlsConfig::from_pem_files(cert_path, key_path)?;
config.auto_reload = true;

// Initial load
let server_config = Arc::new(load_tls_config(config.clone()).await?);

// Watch for changes and reload
watch_certificate_files(config, move |new_config| {
    // Update server configuration
    *server_config.write() = new_config;
}).await?;
```

### Manual Reload (SIGHUP)

Send SIGHUP signal to reload certificates without downtime:

```bash
# Find coordinator PID
pidof coordinator

# Send reload signal
sudo kill -HUP <pid>

# Or with systemd
sudo systemctl reload bitsage-coordinator
```

---

## Security Best Practices

### 1. Use Strong Cipher Suites

The TLS module uses rustls with secure defaults:
- ✅ TLS 1.3 preferred
- ✅ TLS 1.2 as fallback
- ✅ Modern cipher suites only (no RC4, 3DES, MD5)
- ✅ Forward secrecy (ECDHE)
- ✅ No compression (CRIME attack mitigation)

### 2. Certificate Validation

```rust
// Always validate certificates on load
let certs = load_certificates(cert_path)?;
check_certificate_expiry(&certs, 30)?; // Warn if < 30 days

// Verify certificate chain
get_certificate_info(&certs)?; // Logs detailed info
```

### 3. Private Key Protection

```bash
# Restrict key file permissions
sudo chmod 600 /etc/letsencrypt/live/*/privkey.pem
sudo chown bitsage:bitsage /etc/letsencrypt/live/*/privkey.pem

# Use secrets management in production
export TLS_KEY_PATH=$(vault kv get -field=key secret/coordinator/tls)
```

### 4. HTTP Strict Transport Security (HSTS)

Add HSTS headers to enforce HTTPS:

```rust
use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::header::{STRICT_TRANSPORT_SECURITY};

let app = Router::new()
    .route("/api/jobs", post(submit_job))
    .layer(SetResponseHeaderLayer::if_not_present(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload")
    ));
```

### 5. Certificate Pinning (Optional)

For highly sensitive deployments:

```rust
// Store expected certificate fingerprint
const EXPECTED_FINGERPRINT: &str = "AA:BB:CC:DD...";

// Verify on connection
fn verify_certificate_fingerprint(cert: &Certificate) -> bool {
    use sha2::{Sha256, Digest};
    let fingerprint = Sha256::digest(&cert.0);
    format!("{:X}", fingerprint) == EXPECTED_FINGERPRINT
}
```

---

## Monitoring & Alerts

### Certificate Expiry Monitoring

The coordinator logs warnings when certificates are close to expiry:

```
2026-01-02T12:00:00Z WARN coordinator: ⚠️  Certificate 0 expires in 14 days (2026-01-16T12:00:00+00:00)
```

### Prometheus Metrics

Add certificate expiry metrics:

```rust
use prometheus::{register_gauge, Gauge};

lazy_static! {
    static ref CERT_EXPIRY_DAYS: Gauge = register_gauge!(
        "tls_certificate_expiry_days",
        "Days until TLS certificate expiration"
    ).unwrap();
}

// Update on certificate load
CERT_EXPIRY_DAYS.set(days_until_expiry as f64);
```

### Alert Rules

**prometheus/alerts.yml:**
```yaml
groups:
  - name: tls_alerts
    rules:
      - alert: CertificateExpiringSoon
        expr: tls_certificate_expiry_days < 14
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate expiring soon"
          description: "Certificate expires in {{ $value }} days"

      - alert: CertificateExpired
        expr: tls_certificate_expiry_days < 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "TLS certificate EXPIRED"
          description: "Certificate has expired!"
```

---

## Troubleshooting

### Common Issues

#### 1. "Certificate file not found"

```bash
# Check file exists
ls -la /etc/letsencrypt/live/coordinator.bitsage.network/

# Check permissions
sudo chmod 644 /etc/letsencrypt/live/*/fullchain.pem
sudo chmod 600 /etc/letsencrypt/live/*/privkey.pem
```

#### 2. "Failed to parse private key"

```bash
# Verify key format (should be PEM)
openssl rsa -in privkey.pem -text -noout

# Convert from DER to PEM if needed
openssl rsa -inform DER -in privkey.der -outform PEM -out privkey.pem
```

#### 3. "Certificate has EXPIRED"

```bash
# Check expiry date
openssl x509 -in fullchain.pem -noout -enddate

# Renew Let's Encrypt certificate
sudo certbot renew --force-renewal
```

#### 4. "Port 443 already in use"

```bash
# Find process using port
sudo lsof -i :443

# Kill process or change coordinator port
export HTTPS_PORT=8443
```

#### 5. Browser shows "Not Secure"

- Self-signed certificate: Expected (add exception or use Let's Encrypt)
- Missing intermediate certificates: Use `fullchain.pem` not `cert.pem`
- Hostname mismatch: Certificate CN must match domain

---

## Testing

### Local HTTPS Testing

```bash
# Generate self-signed cert
cargo run --example tls_self_signed

# Start coordinator with TLS
TLS_MODE=self-signed TLS_COMMON_NAME=localhost cargo run --bin coordinator

# Test with curl (accept self-signed)
curl -k https://localhost:3443/health

# Test redirect
curl -I http://localhost:8080/health
# Should return 301 redirect to https://localhost:8443/health
```

### Production Testing

```bash
# Test certificate
openssl s_client -connect coordinator.bitsage.network:443 -showcerts

# Test TLS version and ciphers
nmap --script ssl-enum-ciphers -p 443 coordinator.bitsage.network

# Test with SSL Labs
# https://www.ssllabs.com/ssltest/analyze.html?d=coordinator.bitsage.network
```

---

## Summary

✅ **Production-Ready TLS Implementation**

The BitSage coordinator now has enterprise-grade HTTPS support:

- 🔒 **Modern TLS 1.3** with secure cipher suites
- 🎫 **Let's Encrypt Integration** for free, automated certificates
- 🔄 **Auto-Renewal Support** with systemd/cron hooks
- ↗️ **HTTP → HTTPS Redirect** for seamless migration
- 📊 **Certificate Monitoring** with expiry alerts
- 🔐 **Best Practices** enforced by default

**Next Steps:**
1. Obtain Let's Encrypt certificate with certbot
2. Configure environment variables
3. Test certificate loading
4. Enable HTTP redirect
5. Set up monitoring alerts
6. Configure auto-renewal

*Last Updated: 2026-01-02*
