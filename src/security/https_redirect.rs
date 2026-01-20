//! HTTP to HTTPS Redirect Middleware
//!
//! Automatically redirects HTTP requests to HTTPS for production security.

use axum::{
    body::Body,
    extract::Host,
    http::{Request, Response, Uri},
    middleware::Next,
    response::{IntoResponse, Redirect},
};

/// Redirect HTTP requests to HTTPS
///
/// This middleware should be applied to the HTTP server (port 80)
/// to redirect all traffic to HTTPS (port 443).
///
/// ## Example
///
/// ```rust,no_run
/// use axum::{Router, middleware};
/// use bitsage_node::security::https_redirect_middleware;
///
/// let http_app: Router = Router::new()
///     .layer(middleware::from_fn(https_redirect_middleware));
/// ```
pub async fn https_redirect_middleware(
    Host(host): Host,
    uri: Uri,
    _request: Request<Body>,
    _next: Next,
) -> Result<Response<Body>, impl IntoResponse> {
    // Extract host without port
    let host_without_port = host.split(':').next().unwrap_or(&host);

    // Build HTTPS URL
    let https_uri = format!(
        "https://{}{}",
        host_without_port,
        uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    // Return permanent redirect (301)
    Err(Redirect::permanent(&https_uri))
}

/// Advanced HTTP to HTTPS redirect with custom port support
pub async fn https_redirect_to_port(
    https_port: u16,
) -> impl Fn(Host, Uri, Request<Body>, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response<Body>, Redirect>> + Send>>
{
    move |Host(host), uri, _request, _next| {
        Box::pin(async move {
            let host_without_port = host.split(':').next().unwrap_or(&host);

            let https_uri = if https_port == 443 {
                // Standard HTTPS port, don't include in URL
                format!(
                    "https://{}{}",
                    host_without_port,
                    uri.path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/")
                )
            } else {
                // Custom port, include in URL
                format!(
                    "https://{}:{}{}",
                    host_without_port,
                    https_port,
                    uri.path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/")
                )
            };

            Err(Redirect::permanent(&https_uri))
        })
    }
}

/// Health check exception for HTTP redirect
///
/// Allows /health endpoints to work on HTTP without redirect
/// (useful for load balancer health checks).
pub async fn https_redirect_with_health_exception(
    Host(host): Host,
    uri: Uri,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, impl IntoResponse> {
    // Allow health check endpoints on HTTP
    if uri.path().starts_with("/health") {
        return Ok(next.run(request).await);
    }

    let host_without_port = host.split(':').next().unwrap_or(&host);

    let https_uri = format!(
        "https://{}{}",
        host_without_port,
        uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    Err(Redirect::permanent(&https_uri))
}

#[cfg(test)]
mod tests {
    
    

    #[tokio::test]
    async fn test_https_redirect() {
        // This is a placeholder test - full testing would require a test server
        // In production, test with integration tests
    }
}
