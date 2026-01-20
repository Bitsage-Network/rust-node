//! # CAPTCHA Verification Module
//!
//! Provides anti-bot protection for the faucet using Cloudflare Turnstile.
//! Can be configured to use other providers (hCaptcha, reCAPTCHA) in the future.

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn, error};

/// Supported CAPTCHA providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaptchaProvider {
    /// Cloudflare Turnstile (recommended - privacy-focused, free)
    #[default]
    Turnstile,
    /// hCaptcha (privacy-focused alternative)
    HCaptcha,
    /// Google reCAPTCHA v2/v3
    ReCaptcha,
    /// No CAPTCHA verification (development only)
    Disabled,
}

impl CaptchaProvider {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "turnstile" | "cloudflare" => Self::Turnstile,
            "hcaptcha" => Self::HCaptcha,
            "recaptcha" | "google" => Self::ReCaptcha,
            "disabled" | "none" | "off" => Self::Disabled,
            _ => Self::Turnstile, // Default
        }
    }
}

/// CAPTCHA verification configuration
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// Which provider to use
    pub provider: CaptchaProvider,
    /// Secret key for server-side verification
    pub secret_key: String,
    /// Site key for client-side widget (for reference)
    pub site_key: String,
    /// Request timeout
    pub timeout: Duration,
    /// Whether CAPTCHA is required for claims
    pub required: bool,
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        Self {
            provider: CaptchaProvider::Disabled,
            secret_key: String::new(),
            site_key: String::new(),
            timeout: Duration::from_secs(10),
            required: false,
        }
    }
}

impl CaptchaConfig {
    /// Create a new Turnstile configuration
    pub fn turnstile(secret_key: String, site_key: String) -> Self {
        Self {
            provider: CaptchaProvider::Turnstile,
            secret_key,
            site_key,
            timeout: Duration::from_secs(10),
            required: true,
        }
    }

    /// Create a disabled configuration (for development)
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Check if CAPTCHA is enabled
    pub fn is_enabled(&self) -> bool {
        self.provider != CaptchaProvider::Disabled && self.required
    }
}

/// CAPTCHA verifier service
pub struct CaptchaVerifier {
    config: CaptchaConfig,
    http_client: Client,
}

impl CaptchaVerifier {
    /// Create a new CAPTCHA verifier
    pub fn new(config: CaptchaConfig) -> Self {
        let http_client = Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self { config, http_client }
    }

    /// Check if CAPTCHA is required
    pub fn is_required(&self) -> bool {
        self.config.is_enabled()
    }

    /// Verify a CAPTCHA token
    ///
    /// # Arguments
    /// * `token` - The CAPTCHA response token from the client
    /// * `remote_ip` - Optional IP address of the user (for additional validation)
    ///
    /// # Returns
    /// * `Ok(true)` - Token is valid
    /// * `Ok(false)` - Token is invalid
    /// * `Err(_)` - Verification failed (network error, etc.)
    pub async fn verify(&self, token: &str, remote_ip: Option<&str>) -> Result<bool> {
        match self.config.provider {
            CaptchaProvider::Disabled => {
                debug!("CAPTCHA disabled, allowing request");
                Ok(true)
            }
            CaptchaProvider::Turnstile => self.verify_turnstile(token, remote_ip).await,
            CaptchaProvider::HCaptcha => self.verify_hcaptcha(token, remote_ip).await,
            CaptchaProvider::ReCaptcha => self.verify_recaptcha(token, remote_ip).await,
        }
    }

    /// Verify Cloudflare Turnstile token
    async fn verify_turnstile(&self, token: &str, remote_ip: Option<&str>) -> Result<bool> {
        const VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

        #[derive(Serialize)]
        struct TurnstileRequest<'a> {
            secret: &'a str,
            response: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            remoteip: Option<&'a str>,
        }

        #[derive(Deserialize, Debug)]
        struct TurnstileResponse {
            success: bool,
            #[serde(rename = "error-codes")]
            error_codes: Option<Vec<String>>,
            challenge_ts: Option<String>,
            hostname: Option<String>,
        }

        let request = TurnstileRequest {
            secret: &self.config.secret_key,
            response: token,
            remoteip: remote_ip,
        };

        let response = self
            .http_client
            .post(VERIFY_URL)
            .form(&request)
            .send()
            .await
            .map_err(|e| anyhow!("Turnstile request failed: {}", e))?;

        if !response.status().is_success() {
            error!("Turnstile API error: {}", response.status());
            return Err(anyhow!("Turnstile API error: {}", response.status()));
        }

        let result: TurnstileResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse Turnstile response: {}", e))?;

        if !result.success {
            if let Some(errors) = &result.error_codes {
                warn!("Turnstile verification failed: {:?}", errors);
            }
        } else {
            debug!(
                "Turnstile verification successful for hostname: {:?}, challenge_ts: {:?}",
                result.hostname,
                result.challenge_ts
            );
        }

        Ok(result.success)
    }

    /// Verify hCaptcha token
    async fn verify_hcaptcha(&self, token: &str, remote_ip: Option<&str>) -> Result<bool> {
        const VERIFY_URL: &str = "https://hcaptcha.com/siteverify";

        #[derive(Serialize)]
        struct HCaptchaRequest<'a> {
            secret: &'a str,
            response: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            remoteip: Option<&'a str>,
        }

        #[derive(Deserialize)]
        struct HCaptchaResponse {
            success: bool,
            #[serde(rename = "error-codes")]
            error_codes: Option<Vec<String>>,
        }

        let request = HCaptchaRequest {
            secret: &self.config.secret_key,
            response: token,
            remoteip: remote_ip,
        };

        let response = self
            .http_client
            .post(VERIFY_URL)
            .form(&request)
            .send()
            .await
            .map_err(|e| anyhow!("hCaptcha request failed: {}", e))?;

        let result: HCaptchaResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse hCaptcha response: {}", e))?;

        if !result.success {
            if let Some(errors) = &result.error_codes {
                warn!("hCaptcha verification failed: {:?}", errors);
            }
        }

        Ok(result.success)
    }

    /// Verify Google reCAPTCHA token
    async fn verify_recaptcha(&self, token: &str, remote_ip: Option<&str>) -> Result<bool> {
        const VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

        #[derive(Serialize)]
        struct ReCaptchaRequest<'a> {
            secret: &'a str,
            response: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            remoteip: Option<&'a str>,
        }

        #[derive(Deserialize)]
        struct ReCaptchaResponse {
            success: bool,
            score: Option<f32>, // For v3
            #[serde(rename = "error-codes")]
            error_codes: Option<Vec<String>>,
        }

        let request = ReCaptchaRequest {
            secret: &self.config.secret_key,
            response: token,
            remoteip: remote_ip,
        };

        let response = self
            .http_client
            .post(VERIFY_URL)
            .form(&request)
            .send()
            .await
            .map_err(|e| anyhow!("reCAPTCHA request failed: {}", e))?;

        let result: ReCaptchaResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse reCAPTCHA response: {}", e))?;

        if !result.success {
            if let Some(errors) = &result.error_codes {
                warn!("reCAPTCHA verification failed: {:?}", errors);
            }
        }

        // For reCAPTCHA v3, also check the score (0.0-1.0, higher is more likely human)
        if let Some(score) = result.score {
            if score < 0.5 {
                warn!("reCAPTCHA score too low: {}", score);
                return Ok(false);
            }
        }

        Ok(result.success)
    }
}

/// Get CAPTCHA config from environment variables
pub fn config_from_env() -> CaptchaConfig {
    let provider = std::env::var("CAPTCHA_PROVIDER")
        .map(|p| CaptchaProvider::from_str(&p))
        .unwrap_or(CaptchaProvider::Disabled);

    let secret_key = std::env::var("CAPTCHA_SECRET_KEY").unwrap_or_default();
    let site_key = std::env::var("CAPTCHA_SITE_KEY").unwrap_or_default();

    let required = std::env::var("CAPTCHA_REQUIRED")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false);

    CaptchaConfig {
        provider,
        secret_key,
        site_key,
        timeout: Duration::from_secs(10),
        required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_from_str() {
        assert_eq!(CaptchaProvider::from_str("turnstile"), CaptchaProvider::Turnstile);
        assert_eq!(CaptchaProvider::from_str("cloudflare"), CaptchaProvider::Turnstile);
        assert_eq!(CaptchaProvider::from_str("hcaptcha"), CaptchaProvider::HCaptcha);
        assert_eq!(CaptchaProvider::from_str("recaptcha"), CaptchaProvider::ReCaptcha);
        assert_eq!(CaptchaProvider::from_str("disabled"), CaptchaProvider::Disabled);
        assert_eq!(CaptchaProvider::from_str("none"), CaptchaProvider::Disabled);
        assert_eq!(CaptchaProvider::from_str("unknown"), CaptchaProvider::Turnstile);
    }

    #[test]
    fn test_config_is_enabled() {
        let mut config = CaptchaConfig::default();
        assert!(!config.is_enabled());

        config.provider = CaptchaProvider::Turnstile;
        config.required = true;
        assert!(config.is_enabled());

        config.required = false;
        assert!(!config.is_enabled());
    }

    #[tokio::test]
    async fn test_disabled_verification() {
        let config = CaptchaConfig::disabled();
        let verifier = CaptchaVerifier::new(config);

        let result = verifier.verify("any_token", None).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
