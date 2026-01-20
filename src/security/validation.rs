//! Input Validation Middleware
//!
//! Provides request validation for API endpoints.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::warn;

/// Input validation errors
#[derive(Debug)]
pub enum ValidationError {
    InvalidStarknetAddress(String),
    InvalidUrl(String),
    PayloadTooLarge(usize, usize), // actual, max
    InvalidJobType(String),
    SqlInjectionAttempt(String),
    PathTraversalAttempt(String),
    InvalidEmail(String),
}

impl IntoResponse for ValidationError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ValidationError::InvalidStarknetAddress(addr) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid Starknet address: {}", addr),
            ),
            ValidationError::InvalidUrl(url) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid URL: {}", url),
            ),
            ValidationError::PayloadTooLarge(actual, max) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Payload too large: {} bytes (max: {})", actual, max),
            ),
            ValidationError::InvalidJobType(job_type) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid job type: {}", job_type),
            ),
            ValidationError::SqlInjectionAttempt(field) => (
                StatusCode::BAD_REQUEST,
                format!("Potential SQL injection detected in field: {}", field),
            ),
            ValidationError::PathTraversalAttempt(path) => (
                StatusCode::BAD_REQUEST,
                format!("Path traversal attempt detected: {}", path),
            ),
            ValidationError::InvalidEmail(email) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid email address: {}", email),
            ),
        };

        let body = Json(json!({
            "error": message,
            "code": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

/// Validate Starknet address format
pub fn validate_starknet_address(address: &str) -> Result<(), ValidationError> {
    if !address.starts_with("0x") {
        return Err(ValidationError::InvalidStarknetAddress(
            format!("Address must start with 0x: {}", address)
        ));
    }

    // Starknet addresses are felt252 (252 bits) = 32 bytes hex = 64 chars + 0x prefix
    let hex_part = &address[2..];
    if hex_part.len() > 64 {
        return Err(ValidationError::InvalidStarknetAddress(
            format!("Address too long: {}", address)
        ));
    }

    // Validate hex characters
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidStarknetAddress(
            format!("Address contains non-hex characters: {}", address)
        ));
    }

    Ok(())
}

/// Validate URL format
pub fn validate_url(url: &str) -> Result<(), ValidationError> {
    // Basic URL validation
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ValidationError::InvalidUrl(
            format!("URL must start with http:// or https://: {}", url)
        ));
    }

    // Prevent localhost/private IPs in production
    if std::env::var("PRODUCTION").is_ok() {
        if url.contains("localhost") || url.contains("127.0.0.1") || url.contains("0.0.0.0") {
            return Err(ValidationError::InvalidUrl(
                format!("Localhost URLs not allowed in production: {}", url)
            ));
        }
    }

    // Prevent suspicious patterns
    if url.contains("..") {
        return Err(ValidationError::PathTraversalAttempt(url.to_string()));
    }

    Ok(())
}

/// Check for SQL injection patterns
pub fn check_sql_injection(input: &str, field_name: &str) -> Result<(), ValidationError> {
    let suspicious_patterns = [
        "'; DROP TABLE",
        "' OR '1'='1",
        "'; DELETE FROM",
        "' UNION SELECT",
        "'; EXEC",
        "'; INSERT INTO",
        "' AND 1=1--",
        "admin'--",
    ];

    let input_upper = input.to_uppercase();
    for pattern in &suspicious_patterns {
        if input_upper.contains(&pattern.to_uppercase()) {
            warn!(
                field = field_name,
                pattern = pattern,
                "Potential SQL injection detected"
            );
            return Err(ValidationError::SqlInjectionAttempt(field_name.to_string()));
        }
    }

    Ok(())
}

/// Check for path traversal attempts
pub fn check_path_traversal(path: &str) -> Result<(), ValidationError> {
    if path.contains("..") || path.contains("~") {
        warn!(path = path, "Path traversal attempt detected");
        return Err(ValidationError::PathTraversalAttempt(path.to_string()));
    }

    Ok(())
}

/// Validate email address format
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if !email.contains('@') || !email.contains('.') {
        return Err(ValidationError::InvalidEmail(email.to_string()));
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(ValidationError::InvalidEmail(email.to_string()));
    }

    Ok(())
}

/// Middleware to enforce maximum payload size
pub async fn payload_size_limiter(
    request: Request,
    next: Next,
) -> Result<Response, ValidationError> {
    const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10MB

    // Get content-length header
    if let Some(content_length) = request.headers().get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > MAX_PAYLOAD_SIZE {
                    return Err(ValidationError::PayloadTooLarge(length, MAX_PAYLOAD_SIZE));
                }
            }
        }
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_starknet_address() {
        // Valid addresses
        assert!(validate_starknet_address("0x1234567890abcdef").is_ok());
        assert!(validate_starknet_address("0x0").is_ok());

        // Invalid addresses
        assert!(validate_starknet_address("1234").is_err()); // Missing 0x
        assert!(validate_starknet_address("0xzzzz").is_err()); // Non-hex
        let too_long = format!("0x{}", "a".repeat(65));
        assert!(validate_starknet_address(&too_long).is_err());
    }

    #[test]
    fn test_validate_url() {
        // Valid URLs
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://api.starknet.io").is_ok());

        // Invalid URLs
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("https://example.com/../etc/passwd").is_err());
    }

    #[test]
    fn test_sql_injection_detection() {
        assert!(check_sql_injection("normal text", "field").is_ok());
        assert!(check_sql_injection("'; DROP TABLE users--", "field").is_err());
        assert!(check_sql_injection("' OR '1'='1", "field").is_err());
        assert!(check_sql_injection("admin'--", "field").is_err());
    }

    #[test]
    fn test_path_traversal_detection() {
        assert!(check_path_traversal("/normal/path").is_ok());
        assert!(check_path_traversal("../etc/passwd").is_err());
        assert!(check_path_traversal("~/secrets").is_err());
    }

    #[test]
    fn test_email_validation() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
    }
}
