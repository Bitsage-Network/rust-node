//! TLS/HTTPS Certificate Management
//!
//! Provides production-ready TLS support for the BitSage coordinator with:
//! - File-based certificate loading
//! - Self-signed certificate generation (dev/testing)
//! - Certificate validation and expiry checking
//! - Automatic certificate rotation
//! - Support for Let's Encrypt certificates
//!
//! ## Usage
//!
//! ```rust,no_run
//! use bitsage_node::security::tls::{TlsConfig, TlsMode, load_tls_config};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Production: Load from PEM files
//! let config = TlsConfig::from_pem_files(
//!     "/etc/letsencrypt/live/coordinator.bitsage.network/fullchain.pem",
//!     "/etc/letsencrypt/live/coordinator.bitsage.network/privkey.pem"
//! )?;
//!
//! // Development: Generate self-signed certificate
//! let config = TlsConfig::self_signed("localhost")?;
//!
//! // Use with axum-server
//! let tls_config = load_tls_config(config).await?;
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result, anyhow};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{self as tokio_time, Duration as TokioDuration};
use tracing::{info, warn, debug};
use serde::{Deserialize, Serialize};

// =============================================================================
// TLS Configuration Types
// =============================================================================

/// TLS mode configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Disabled - HTTP only (not recommended for production)
    Disabled,
    /// File-based certificates (custom or Let's Encrypt)
    File {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// Self-signed certificate (development only)
    SelfSigned {
        common_name: String,
    },
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// TLS mode
    pub mode: TlsMode,

    /// Enable HTTP to HTTPS redirect
    #[serde(default = "default_true")]
    pub enable_redirect: bool,

    /// HTTP redirect port (default: 80)
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// HTTPS port (default: 443)
    #[serde(default = "default_https_port")]
    pub https_port: u16,

    /// Certificate expiry warning threshold (days)
    #[serde(default = "default_expiry_warning")]
    pub expiry_warning_days: u64,

    /// Enable automatic certificate reload on file changes
    #[serde(default = "default_true")]
    pub auto_reload: bool,
}

fn default_true() -> bool { true }
fn default_http_port() -> u16 { 80 }
fn default_https_port() -> u16 { 443 }
fn default_expiry_warning() -> u64 { 30 }

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::Disabled,
            enable_redirect: true,
            http_port: 80,
            https_port: 443,
            expiry_warning_days: 30,
            auto_reload: true,
        }
    }
}

impl TlsConfig {
    /// Create config from PEM files (production)
    pub fn from_pem_files<P: AsRef<Path>>(cert_path: P, key_path: P) -> Result<Self> {
        let cert_path = cert_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();

        // Validate files exist
        if !cert_path.exists() {
            return Err(anyhow!("Certificate file not found: {}", cert_path.display()));
        }
        if !key_path.exists() {
            return Err(anyhow!("Private key file not found: {}", key_path.display()));
        }

        Ok(Self {
            mode: TlsMode::File { cert_path, key_path },
            ..Default::default()
        })
    }

    /// Create self-signed certificate (development only)
    pub fn self_signed(common_name: &str) -> Result<Self> {
        Ok(Self {
            mode: TlsMode::SelfSigned {
                common_name: common_name.to_string(),
            },
            enable_redirect: false, // No redirect for dev
            ..Default::default()
        })
    }

    /// Load from environment variables
    pub fn from_env() -> Result<Self> {
        let mode = match std::env::var("TLS_MODE")?.as_str() {
            "disabled" => TlsMode::Disabled,
            "file" => {
                let cert_path = std::env::var("TLS_CERT_PATH")
                    .context("TLS_CERT_PATH required for file mode")?;
                let key_path = std::env::var("TLS_KEY_PATH")
                    .context("TLS_KEY_PATH required for file mode")?;
                TlsMode::File {
                    cert_path: PathBuf::from(cert_path),
                    key_path: PathBuf::from(key_path),
                }
            }
            "self-signed" => {
                let common_name = std::env::var("TLS_COMMON_NAME")
                    .unwrap_or_else(|_| "localhost".to_string());
                TlsMode::SelfSigned { common_name }
            }
            mode => return Err(anyhow!("Invalid TLS_MODE: {}", mode)),
        };

        Ok(Self {
            mode,
            enable_redirect: std::env::var("TLS_ENABLE_REDIRECT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            http_port: std::env::var("HTTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(80),
            https_port: std::env::var("HTTPS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(443),
            expiry_warning_days: std::env::var("TLS_EXPIRY_WARNING_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            auto_reload: std::env::var("TLS_AUTO_RELOAD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        })
    }
}

// =============================================================================
// Certificate Loading
// =============================================================================

/// Load certificates from PEM file
pub fn load_certificates(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open certificate file: {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse certificates: {}", e))?;

    if certs.is_empty() {
        return Err(anyhow!("No certificates found in file: {}", path.display()));
    }

    info!("✅ Loaded {} certificate(s) from {}", certs.len(), path.display());

    Ok(certs)
}

/// Load private key from PEM file
pub fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open private key file: {}", path.display()))?;
    let mut reader = BufReader::new(file);

    // Try PKCS8 format first
    let pkcs8_keys: Vec<_> = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse PKCS8 private key: {}", e))?;

    if !pkcs8_keys.is_empty() {
        if pkcs8_keys.len() > 1 {
            warn!("Multiple private keys found, using first one");
        }
        info!("✅ Loaded private key from {} (PKCS8 format)", path.display());
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_keys.into_iter().next().unwrap()));
    }

    // Try RSA format
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let rsa_keys: Vec<_> = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();

    if !rsa_keys.is_empty() {
        if rsa_keys.len() > 1 {
            warn!("Multiple private keys found, using first one");
        }
        info!("✅ Loaded private key from {} (RSA format)", path.display());
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(rsa_keys.into_iter().next().unwrap()));
    }

    Err(anyhow!("No private keys found in file: {}", path.display()))
}

/// Generate self-signed certificate for development
pub fn generate_self_signed_cert(common_name: &str) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
    use rcgen::{Certificate as RcGenCert, CertificateParams, DistinguishedName};

    let mut params = CertificateParams::new(vec![common_name.to_string()]);

    // Set subject
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name);
    dn.push(rcgen::DnType::OrganizationName, "BitSage Network");
    dn.push(rcgen::DnType::OrganizationalUnitName, "Development");
    params.distinguished_name = dn;

    // Set validity period (90 days)
    // rcgen uses time crate's OffsetDateTime
    let now = time::OffsetDateTime::now_utc();
    let ninety_days_later = now + time::Duration::days(90);
    params.not_before = now;
    params.not_after = ninety_days_later;

    // Add subject alternative names
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName(common_name.to_string()),
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let cert = RcGenCert::from_params(params)
        .context("Failed to generate self-signed certificate")?;

    // Serialize certificate
    let cert_der = cert.serialize_der()
        .context("Failed to serialize certificate")?;
    let key_der = cert.serialize_private_key_der();

    // Convert to rustls types
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());

    info!("✅ Generated self-signed certificate for '{}'", common_name);
    warn!("⚠️  Self-signed certificates are for DEVELOPMENT ONLY");

    Ok((certs, key))
}

// =============================================================================
// TLS Server Configuration
// =============================================================================

/// Load TLS configuration and build ServerConfig
pub async fn load_tls_config(config: TlsConfig) -> Result<ServerConfig> {
    let (certs, key) = match &config.mode {
        TlsMode::Disabled => {
            return Err(anyhow!("TLS is disabled"));
        }

        TlsMode::File { cert_path, key_path } => {
            info!("📜 Loading certificates from files");
            let certs = load_certificates(cert_path)?;
            let key = load_private_key(key_path)?;

            // Check certificate expiry
            check_certificate_expiry(&certs, config.expiry_warning_days)?;

            (certs, key)
        }

        TlsMode::SelfSigned { common_name } => {
            info!("🔧 Generating self-signed certificate");
            generate_self_signed_cert(common_name)?
        }
    };

    // Build ServerConfig with rustls 0.22 API
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS server configuration")?;

    info!("🔒 TLS configuration loaded successfully");

    Ok(tls_config)
}

// =============================================================================
// Certificate Validation
// =============================================================================

/// Check certificate expiry and warn if close to expiration
pub fn check_certificate_expiry(certs: &[rustls::pki_types::CertificateDer], warning_days: u64) -> Result<()> {
    use x509_parser::prelude::*;

    for (i, cert) in certs.iter().enumerate() {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| anyhow!("Failed to parse certificate {}: {}", i, e))?;

        let not_after = parsed.validity().not_after;
        let expiry_timestamp = not_after.timestamp();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        let days_until_expiry = (expiry_timestamp - now) / 86400;

        if days_until_expiry < 0 {
            return Err(anyhow!("Certificate {} has EXPIRED", i));
        }

        if days_until_expiry <= warning_days as i64 {
            warn!(
                "⚠️  Certificate {} expires in {} days",
                i,
                days_until_expiry
            );
        } else {
            debug!(
                "Certificate {} valid for {} days",
                i,
                days_until_expiry
            );
        }
    }

    Ok(())
}

/// Watch for certificate file changes and reload
pub async fn watch_certificate_files(
    config: TlsConfig,
    reload_callback: impl Fn(ServerConfig) + Send + 'static,
) -> Result<()> {
    if !config.auto_reload {
        debug!("Auto-reload disabled, skipping certificate watcher");
        return Ok(());
    }

    // Verify we have file-based TLS mode before spawning watcher
    if !matches!(&config.mode, TlsMode::File { .. }) {
        debug!("Certificate watching only supported for file-based mode");
        return Ok(());
    }

    tokio::spawn(async move {
        let mut interval = tokio_time::interval(TokioDuration::from_secs(3600)); // Check every hour

        loop {
            interval.tick().await;

            debug!("Checking for certificate changes");

            match load_tls_config(config.clone()).await {
                Ok(new_config) => {
                    info!("🔄 Reloaded TLS certificates");
                    reload_callback(new_config);
                }
                Err(e) => {
                    warn!("Failed to reload certificates: {}", e);
                }
            }
        }
    });

    info!("👀 Started certificate file watcher (checks every hour)");

    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if TLS is enabled
pub fn is_tls_enabled(config: &TlsConfig) -> bool {
    !matches!(config.mode, TlsMode::Disabled)
}

/// Get certificate information as string
pub fn get_certificate_info(certs: &[rustls::pki_types::CertificateDer]) -> Result<String> {
    use x509_parser::prelude::*;

    let mut info = String::new();

    for (i, cert) in certs.iter().enumerate() {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| anyhow!("Failed to parse certificate {}: {}", i, e))?;

        info.push_str(&format!("Certificate {}:\n", i));
        info.push_str(&format!("  Subject: {}\n", parsed.subject()));
        info.push_str(&format!("  Issuer: {}\n", parsed.issuer()));
        info.push_str(&format!("  Serial: {:x}\n", parsed.serial));
        info.push_str(&format!("  Valid from: {} UTC\n", parsed.validity().not_before));
        info.push_str(&format!("  Valid until: {} UTC\n", parsed.validity().not_after));

        if let Ok(Some(san)) = parsed.subject_alternative_name() {
            info.push_str("  Subject Alternative Names:\n");
            for name in &san.value.general_names {
                info.push_str(&format!("    - {:?}\n", name));
            }
        }

        info.push('\n');
    }

    Ok(info)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(matches!(config.mode, TlsMode::Disabled));
        assert!(config.enable_redirect);
        assert_eq!(config.http_port, 80);
        assert_eq!(config.https_port, 443);
    }

    #[test]
    fn test_self_signed_certificate_generation() {
        let result = generate_self_signed_cert("test.local");
        assert!(result.is_ok());

        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_certificate_info() {
        let (certs, _key) = generate_self_signed_cert("test.local").unwrap();
        let info = get_certificate_info(&certs).unwrap();

        assert!(info.contains("test.local"));
        assert!(info.contains("BitSage Network"));
    }

    #[tokio::test]
    async fn test_self_signed_config_load() {
        let config = TlsConfig::self_signed("localhost").unwrap();
        let server_config = load_tls_config(config).await;
        assert!(server_config.is_ok());
    }
}
