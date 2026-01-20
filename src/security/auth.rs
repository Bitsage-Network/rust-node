//! JWT Authentication Module
//!
//! Provides JWT token generation and validation for API authentication.
//!
//! ## Features
//! - Worker API key generation and validation
//! - JWT token generation with claims
//! - Token expiration and refresh
//! - Role-based access control (RBAC)

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (worker ID or user ID)
    pub sub: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Role (worker, admin, client)
    pub role: Role,
    /// Optional wallet address
    pub wallet: Option<String>,
    /// JWT ID for revocation
    pub jti: String,
}

/// User/Worker role for RBAC
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Worker node (can submit results, receive jobs)
    Worker,
    /// Client (can submit jobs, query results)
    Client,
    /// Admin (full access)
    Admin,
    /// Validator (can validate results)
    Validator,
}

/// JWT authentication configuration
#[derive(Clone)]
pub struct AuthConfig {
    /// Secret key for signing JWTs
    jwt_secret: String,
    /// Token expiration duration (default: 24 hours)
    token_expiry: Duration,
    /// Refresh token expiration (default: 7 days)
    refresh_expiry: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        // Check if we're in production mode
        let is_production = std::env::var("BITSAGE_ENV")
            .map(|v| v.to_lowercase() == "production" || v.to_lowercase() == "mainnet")
            .unwrap_or(false);

        let jwt_secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| {
                if is_production {
                    panic!("CRITICAL: JWT_SECRET environment variable is required in production mode. Set BITSAGE_ENV=development to use insecure defaults for testing.");
                }
                warn!("⚠️  JWT_SECRET not set, using insecure default. This is only acceptable in development!");
                warn!("⚠️  Set JWT_SECRET environment variable before deploying to production.");
                "insecure-default-secret-change-me-dev-only".to_string()
            });

        Self {
            jwt_secret,
            token_expiry: Duration::hours(24),
            refresh_expiry: Duration::days(7),
        }
    }
}

impl AuthConfig {
    /// Create a new AuthConfig (for testing)
    #[cfg(test)]
    pub fn new(jwt_secret: String, token_expiry: Duration, refresh_expiry: Duration) -> Self {
        Self {
            jwt_secret,
            token_expiry,
            refresh_expiry,
        }
    }

    /// Create config from environment with validation
    pub fn from_env() -> Result<Self> {
        let jwt_secret = std::env::var("JWT_SECRET")
            .context("JWT_SECRET environment variable not set")?;

        if jwt_secret.len() < 32 {
            anyhow::bail!("JWT_SECRET must be at least 32 characters");
        }

        if std::env::var("PRODUCTION").is_ok() && jwt_secret == "insecure-default-secret-change-me" {
            anyhow::bail!("JWT_SECRET must be changed in production");
        }

        let token_expiry_hours = std::env::var("JWT_TOKEN_EXPIRY_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);

        let refresh_expiry_days = std::env::var("JWT_REFRESH_EXPIRY_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(7);

        Ok(Self {
            jwt_secret,
            token_expiry: Duration::hours(token_expiry_hours),
            refresh_expiry: Duration::days(refresh_expiry_days),
        })
    }

    /// Get JWT secret as bytes
    fn secret_bytes(&self) -> &[u8] {
        self.jwt_secret.as_bytes()
    }
}

/// JWT token manager
pub struct JwtManager {
    config: Arc<AuthConfig>,
}

impl JwtManager {
    /// Create new JWT manager
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Generate access token for a worker/user
    pub fn generate_token(
        &self,
        subject: String,
        role: Role,
        wallet: Option<String>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + self.config.token_expiry;

        let claims = Claims {
            sub: subject.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            role: role.clone(),
            wallet: wallet.clone(),
            jti: Uuid::new_v4().to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.secret_bytes()),
        )
        .context("Failed to encode JWT")?;

        debug!(
            subject = %subject,
            role = ?role,
            expires_at = %exp,
            "Generated JWT token"
        );

        Ok(token)
    }

    /// Generate refresh token (longer expiry)
    pub fn generate_refresh_token(
        &self,
        subject: String,
        role: Role,
        wallet: Option<String>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + self.config.refresh_expiry;

        let claims = Claims {
            sub: subject.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            role,
            wallet,
            jti: Uuid::new_v4().to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.secret_bytes()),
        )
        .context("Failed to encode refresh token")?;

        debug!(
            subject = %subject,
            expires_at = %exp,
            "Generated refresh token"
        );

        Ok(token)
    }

    /// Validate and decode JWT token
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::default();

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.secret_bytes()),
            &validation,
        )
        .context("Failed to decode JWT")?;

        debug!(
            subject = %token_data.claims.sub,
            role = ?token_data.claims.role,
            "Validated JWT token"
        );

        Ok(token_data.claims)
    }

    /// Verify token has required role
    pub fn verify_role(&self, token: &str, required_role: Role) -> Result<Claims> {
        let claims = self.validate_token(token)?;

        if claims.role != required_role && claims.role != Role::Admin {
            anyhow::bail!("Insufficient permissions: required {:?}, has {:?}", required_role, claims.role);
        }

        Ok(claims)
    }

    /// Extract token from Authorization header
    pub fn extract_bearer_token(auth_header: &str) -> Result<&str> {
        if !auth_header.starts_with("Bearer ") {
            anyhow::bail!("Invalid Authorization header format. Expected: Bearer <token>");
        }

        Ok(&auth_header[7..])
    }
}

/// API key for workers (simpler alternative to JWT for worker-to-coordinator auth)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiKey {
    /// Unique API key ID
    pub key_id: String,
    /// Hashed API key (bcrypt)
    pub key_hash: String,
    /// Associated worker/user ID
    pub owner_id: String,
    /// Role
    pub role: Role,
    /// Creation timestamp
    pub created_at: i64,
    /// Optional expiration timestamp
    pub expires_at: Option<i64>,
    /// Whether the key is active
    pub is_active: bool,
}

/// API key manager
pub struct ApiKeyManager;

impl ApiKeyManager {
    /// Generate new API key
    pub fn generate() -> (String, String) {
        let key_id = Uuid::new_v4().to_string();
        let api_key = format!("sk_{}", Uuid::new_v4().simple());
        (key_id, api_key)
    }

    /// Hash API key for storage
    pub fn hash_key(api_key: &str) -> Result<String> {
        let hash = bcrypt::hash(api_key, bcrypt::DEFAULT_COST)
            .context("Failed to hash API key")?;
        Ok(hash)
    }

    /// Verify API key against hash
    pub fn verify_key(api_key: &str, hash: &str) -> Result<bool> {
        let verified = bcrypt::verify(api_key, hash)
            .context("Failed to verify API key")?;
        Ok(verified)
    }

    /// Extract API key from header
    pub fn extract_api_key(header: &str) -> Result<&str> {
        if !header.starts_with("ApiKey ") && !header.starts_with("Bearer ") {
            anyhow::bail!("Invalid Authorization header format. Expected: ApiKey <key> or Bearer <key>");
        }

        let start = if header.starts_with("ApiKey ") { 7 } else { 7 };
        Ok(&header[start..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_generation_and_validation() {
        let config = AuthConfig {
            jwt_secret: "test-secret-key-at-least-32-chars-long".to_string(),
            token_expiry: Duration::hours(1),
            refresh_expiry: Duration::days(7),
        };

        let manager = JwtManager::new(config);

        // Generate token
        let token = manager
            .generate_token("worker-123".to_string(), Role::Worker, None)
            .unwrap();

        // Validate token
        let claims = manager.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "worker-123");
        assert_eq!(claims.role, Role::Worker);
    }

    #[test]
    fn test_role_verification() {
        let config = AuthConfig {
            jwt_secret: "test-secret-key-at-least-32-chars-long".to_string(),
            token_expiry: Duration::hours(1),
            refresh_expiry: Duration::days(7),
        };

        let manager = JwtManager::new(config);

        // Generate worker token
        let token = manager
            .generate_token("worker-123".to_string(), Role::Worker, None)
            .unwrap();

        // Verify worker role - should pass
        assert!(manager.verify_role(&token, Role::Worker).is_ok());

        // Verify admin role - should fail
        assert!(manager.verify_role(&token, Role::Admin).is_err());
    }

    #[test]
    fn test_api_key_generation() {
        let (key_id, api_key) = ApiKeyManager::generate();
        assert!(key_id.len() > 0);
        assert!(api_key.starts_with("sk_"));

        // Hash and verify
        let hash = ApiKeyManager::hash_key(&api_key).unwrap();
        assert!(ApiKeyManager::verify_key(&api_key, &hash).unwrap());

        // Wrong key should fail
        assert!(!ApiKeyManager::verify_key("wrong-key", &hash).unwrap());
    }

    #[test]
    fn test_bearer_token_extraction() {
        let header = "Bearer abc123token";
        let token = JwtManager::extract_bearer_token(header).unwrap();
        assert_eq!(token, "abc123token");

        // Invalid format
        let invalid = "InvalidFormat";
        assert!(JwtManager::extract_bearer_token(invalid).is_err());
    }
}
