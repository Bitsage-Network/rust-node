//! Security Module
//!
//! Provides TEE attestation, secure GPU proof generation, authentication, and input validation.
//!
//! ## Components
//!
//! - `tee`: TEE hardware attestation (TDX, SEV-SNP)
//! - `gpu_tee`: GPU-accelerated secure proof generation
//! - `auth`: JWT and API key authentication
//! - `middleware`: Authentication middleware for Axum
//! - `validation`: Input validation and sanitization
//! - `tls`: TLS/HTTPS certificate management

pub mod tee;
pub mod gpu_tee;
pub mod auth;
pub mod middleware;
pub mod validation;
pub mod tls;
pub mod https_redirect;

pub use tee::*;
pub use gpu_tee::{
    GpuSecureProver, GpuTeeConfig, SessionKey, EncryptedPayload,
    SecureProofResult, SecureProofMetrics,
};
pub use auth::{
    AuthConfig, JwtManager, ApiKeyManager, ApiKey, Claims, Role,
};
pub use middleware::{
    auth_middleware, optional_auth_middleware, require_role,
    AuthenticatedUser, AuthError,
};
pub use validation::{
    validate_starknet_address, validate_url, check_sql_injection,
    check_path_traversal, validate_email, payload_size_limiter,
    ValidationError,
};
pub use tls::{
    TlsConfig, TlsMode, load_tls_config, load_certificates, load_private_key,
    generate_self_signed_cert, check_certificate_expiry, is_tls_enabled,
    get_certificate_info,
};
pub use https_redirect::{
    https_redirect_middleware, https_redirect_to_port,
    https_redirect_with_health_exception,
};

