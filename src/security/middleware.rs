//! Authentication Middleware for Axum
//!
//! Provides middleware for JWT and API key authentication in Axum routes.

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use super::auth::{Claims, JwtManager, Role};

/// Authentication error responses
#[derive(Debug)]
pub enum AuthError {
    MissingAuth,
    InvalidToken,
    InsufficientPermissions,
    ExpiredToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingAuth => (
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header",
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid or malformed token",
            ),
            AuthError::InsufficientPermissions => (
                StatusCode::FORBIDDEN,
                "Insufficient permissions for this operation",
            ),
            AuthError::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                "Token has expired",
            ),
        };

        let body = Json(json!({
            "error": message,
            "code": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

/// Extension to add authenticated user info to request
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub role: Role,
    pub wallet: Option<String>,
}

impl From<Claims> for AuthenticatedUser {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub,
            role: claims.role,
            wallet: claims.wallet,
        }
    }
}

/// Authentication middleware - validates JWT token
pub async fn auth_middleware(
    State(jwt_manager): State<Arc<JwtManager>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthError::MissingAuth)?;

    debug!("Processing authentication for request");

    // Extract and validate token
    let token = JwtManager::extract_bearer_token(auth_header)
        .map_err(|e| {
            warn!("Failed to extract bearer token: {}", e);
            AuthError::InvalidToken
        })?;

    let claims = jwt_manager
        .validate_token(token)
        .map_err(|e| {
            warn!("Token validation failed: {}", e);
            AuthError::InvalidToken
        })?;

    // Add authenticated user to request extensions
    let user = AuthenticatedUser::from(claims);
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Role-based authentication middleware
pub fn require_role(required_role: Role) -> impl Fn(State<Arc<JwtManager>>, Request, Next) -> futures::future::BoxFuture<'static, Result<Response, AuthError>> + Clone {
    move |State(jwt_manager): State<Arc<JwtManager>>, mut request: Request, next: Next| {
        let role = required_role.clone();
        Box::pin(async move {
            // Extract Authorization header
            let auth_header = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .ok_or(AuthError::MissingAuth)?;

            // Extract and validate token with role check
            let token = JwtManager::extract_bearer_token(auth_header)
                .map_err(|_| AuthError::InvalidToken)?;

            let claims = jwt_manager
                .verify_role(token, role)
                .map_err(|e| {
                    warn!("Role verification failed: {}", e);
                    AuthError::InsufficientPermissions
                })?;

            // Add authenticated user to request extensions
            let user = AuthenticatedUser::from(claims);
            request.extensions_mut().insert(user);

            Ok(next.run(request).await)
        })
    }
}

/// Optional authentication middleware - doesn't fail if no auth present
pub async fn optional_auth_middleware(
    State(jwt_manager): State<Arc<JwtManager>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to extract Authorization header
    if let Some(auth_header) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        // Try to validate token
        if let Ok(token) = JwtManager::extract_bearer_token(auth_header) {
            if let Ok(claims) = jwt_manager.validate_token(token) {
                let user = AuthenticatedUser::from(claims);
                request.extensions_mut().insert(user);
            }
        }
    }

    // Continue regardless of auth status
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::auth::AuthConfig;
    use axum::{
        body::Body,
        http::Request as HttpRequest,
        middleware,
        routing::get,
        Router,
    };
    use tower::Service;

    #[tokio::test]
    async fn test_auth_middleware_with_valid_token() {
        let config = AuthConfig::new(
            "test-secret-key-at-least-32-chars-long".to_string(),
            chrono::Duration::hours(1),
            chrono::Duration::days(7),
        );

        let manager = Arc::new(JwtManager::new(config));
        let token = manager
            .generate_token("user-123".to_string(), Role::Worker, None)
            .unwrap();

        // Create test app
        let app = Router::new()
            .route(
                "/test",
                get(|| async { "success" }),
            )
            .layer(middleware::from_fn_with_state(
                manager.clone(),
                auth_middleware,
            ))
            .with_state(manager);

        // Create request with valid token
        let request = HttpRequest::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let mut service = app.into_service();
        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_without_token() {
        let config = AuthConfig::new(
            "test-secret-key-at-least-32-chars-long".to_string(),
            chrono::Duration::hours(1),
            chrono::Duration::days(7),
        );

        let manager = Arc::new(JwtManager::new(config));

        // Create test app
        let app = Router::new()
            .route(
                "/test",
                get(|| async { "success" }),
            )
            .layer(middleware::from_fn_with_state(
                manager.clone(),
                auth_middleware,
            ))
            .with_state(manager);

        // Create request without token
        let request = HttpRequest::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let mut service = app.into_service();
        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
