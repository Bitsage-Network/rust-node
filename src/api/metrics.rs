//! Prometheus Metrics Endpoint
//!
//! HTTP endpoint for Prometheus to scrape consensus metrics.
//!
//! ## Usage
//!
//! ```rust
//! use axum::Router;
//! use bitsage_node::api::metrics::metrics_routes;
//!
//! let app = Router::new()
//!     .merge(metrics_routes());
//! ```
//!
//! ## Endpoints
//!
//! - `GET /metrics` - Prometheus metrics in text format

use axum::{
    routing::get,
    Router,
    http::StatusCode,
    response::IntoResponse,
};

use crate::validator::metrics as consensus_metrics;

/// Prometheus metrics handler
///
/// Returns metrics in Prometheus text format
async fn metrics_handler() -> impl IntoResponse {
    let metrics = consensus_metrics::gather_metrics();
    (StatusCode::OK, metrics)
}

/// Health check endpoint
///
/// Returns 200 OK if the service is healthy
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "healthy")
}

/// Create metrics routes
pub fn metrics_routes() -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = metrics_routes();

        let request = Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = metrics_routes();

        let request = Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
