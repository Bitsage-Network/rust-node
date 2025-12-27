//! # Simple BitSage Coordinator
//!
//! Lightweight coordinator for testing and development

use std::net::SocketAddr;
use clap::Parser;
use tracing::info;
use anyhow::Result;
use axum::{Router, routing::get, Json};
use tower_http::cors::CorsLayer;
use tokio::signal;

#[derive(Parser)]
#[command(name = "bitsage-simple-coordinator")]
#[command(about = "Simple BitSage Coordinator for Testing")]
#[command(version)]
struct Cli {
    /// HTTP API port
    #[arg(short, long, default_value = "8080")]
    port: u16,
    
    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();
    
    // Parse CLI args
    let cli = Cli::parse();
    
    info!("🚀 Starting Simple BitSage Coordinator...");
    info!("📡 This is a simplified version for testing");
    
    // TODO: Initialize actual services
    // For now, create placeholder router
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/api/health", get(health_handler))
        .layer(CorsLayer::permissive());
    
    // Start HTTP server
    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;
    info!("🌐 Starting HTTP API server on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    info!("✅ Simple Coordinator is running!");
    info!("📡 API: http://{}", addr);
    info!("📊 Health: http://{}/api/health", addr);
    info!("");
    info!("⚠️  NOTE: This is a simplified coordinator for testing");
    info!("⚠️  Use the full coordinator binary for production");
    info!("");
    info!("Press Ctrl+C to shutdown...");
    
    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    
    info!("✅ Coordinator stopped cleanly");
    
    Ok(())
}

/// Root handler
async fn root_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "BitSage Network Simple Coordinator",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
        "note": "This is a simplified coordinator for testing"
    }))
}

/// Health check handler
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp()
    }))
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}

