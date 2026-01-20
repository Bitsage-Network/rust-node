//! Dashboard API Integration Tests
//!
//! Tests the validator dashboard REST API endpoints.
//! These tests can run against a local coordinator or mock the database.

use bitsage_node::api::{
    dashboard::{
        DashboardApiState, DashboardContracts,
        NetworkStatsResponse, ContractsResponse, JobAnalyticsResponse,
        ValidatorStatusResponse, NetworkWorkersResponse,
    },
    cache::{DashboardCache, CacheConfig},
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use serde_json::Value;
use std::sync::Arc;

/// Helper to create test dashboard state without database
fn create_test_dashboard_state() -> Arc<DashboardApiState> {
    Arc::new(DashboardApiState {
        network: "sepolia".to_string(),
        contracts: DashboardContracts {
            sage_token: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
            prover_staking: "0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b".to_string(),
            reputation_manager: "0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de".to_string(),
            job_manager: "0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3".to_string(),
            faucet: Some("0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3".to_string()),
        },
        metrics_aggregator: None,
        db: None, // No database for unit tests
        cache: Some(Arc::new(DashboardCache::new_memory(CacheConfig::default()))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitsage_node::api::dashboard::dashboard_routes;

    #[tokio::test]
    async fn test_contracts_endpoint() {
        let state = create_test_dashboard_state();
        let app = dashboard_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/contracts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: ContractsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(json.network, "sepolia");
        assert!(json.sage_token.starts_with("0x"));
        assert!(json.prover_staking.starts_with("0x"));
        assert!(json.faucet.is_some());
        println!("✅ Contracts endpoint test passed!");
    }

    #[tokio::test]
    async fn test_network_stats_endpoint_no_db() {
        let state = create_test_dashboard_state();
        let app = dashboard_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/network/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: NetworkStatsResponse = serde_json::from_slice(&body).unwrap();

        // Without database, should return defaults
        assert_eq!(json.network, "sepolia");
        assert_eq!(json.total_workers, 0);
        assert_eq!(json.active_workers, 0);
        assert_eq!(json.total_jobs_processed, 0);
        println!("✅ Network stats (no DB) test passed!");
    }

    #[tokio::test]
    async fn test_validator_status_endpoint_no_metrics() {
        let state = create_test_dashboard_state();
        let app = dashboard_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/validator/status")
                    .header("X-Wallet-Address", "0x123456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: ValidatorStatusResponse = serde_json::from_slice(&body).unwrap();

        // Without metrics aggregator, should return defaults
        assert!(!json.is_active);
        assert!(!json.is_registered);
        assert_eq!(json.staked_amount, "0");
        assert_eq!(json.reputation_score, 0);
        println!("✅ Validator status (no metrics) test passed!");
    }

    #[tokio::test]
    async fn test_job_analytics_endpoint_no_db() {
        let state = create_test_dashboard_state();
        let app = dashboard_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/jobs/analytics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: JobAnalyticsResponse = serde_json::from_slice(&body).unwrap();

        // Without database, should return defaults
        assert_eq!(json.total_jobs, 0);
        assert_eq!(json.jobs_completed, 0);
        assert_eq!(json.jobs_failed, 0);
        assert_eq!(json.success_rate, 0.0);
        println!("✅ Job analytics (no DB) test passed!");
    }

    #[tokio::test]
    async fn test_network_workers_endpoint_no_db() {
        let state = create_test_dashboard_state();
        let app = dashboard_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/network/workers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: NetworkWorkersResponse = serde_json::from_slice(&body).unwrap();

        // Without database, should return empty list
        assert!(json.workers.is_empty());
        assert_eq!(json.total_count, 0);
        println!("✅ Network workers (no DB) test passed!");
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let cache = DashboardCache::new_memory(CacheConfig::default());

        // Test basic set/get
        cache.set("test:key", &"test_value".to_string(), 60).await;
        let value: Option<String> = cache.get("test:key").await;
        assert_eq!(value, Some("test_value".to_string()));

        // Test complex type
        let stats = NetworkStatsResponse {
            network: "test".to_string(),
            total_workers: 10,
            active_workers: 5,
            total_jobs_processed: 1000,
            jobs_last_24h: 50,
            avg_job_completion_time_secs: 12.5,
            total_compute_hours: 100.0,
            network_utilization: 50.0,
            total_staked: "1000000".to_string(),
            total_staked_formatted: "1,000,000 SAGE".to_string(),
            current_block: 12345,
        };

        cache.set("network:stats", &stats, 60).await;
        let cached_stats: Option<NetworkStatsResponse> = cache.get("network:stats").await;
        assert!(cached_stats.is_some());
        assert_eq!(cached_stats.unwrap().total_workers, 10);

        // Test delete
        cache.delete("test:key").await;
        let deleted: Option<String> = cache.get("test:key").await;
        assert!(deleted.is_none());

        // Test stats
        let cache_stats = cache.stats();
        assert!(cache_stats.enabled);
        println!("✅ Cache functionality test passed!");
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        let config = CacheConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = DashboardCache::new_memory(config);

        cache.set("test:disabled", &"value".to_string(), 60).await;
        let value: Option<String> = cache.get("test:disabled").await;

        // When disabled, cache should return None
        assert!(value.is_none());
        println!("✅ Cache disabled test passed!");
    }
}

/// Integration tests that require a running database
/// These are marked with #[ignore] and can be run with:
/// `cargo test --test dashboard_integration_test -- --ignored`
#[cfg(test)]
mod database_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    /// Get database URL from environment or use default
    fn get_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://bitsage:bitsage_dev_password@localhost:5432/sage".to_string())
    }

    /// Create dashboard state with database connection
    async fn create_db_dashboard_state() -> Result<Arc<DashboardApiState>, sqlx::Error> {
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&get_database_url())
            .await?;

        Ok(Arc::new(DashboardApiState {
            network: "sepolia".to_string(),
            contracts: DashboardContracts {
                sage_token: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
                prover_staking: "0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b".to_string(),
                reputation_manager: "0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de".to_string(),
                job_manager: "0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3".to_string(),
                faucet: Some("0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3".to_string()),
            },
            metrics_aggregator: None,
            db: Some(db),
            cache: Some(Arc::new(DashboardCache::new_memory(CacheConfig::default()))),
        }))
    }

    #[tokio::test]
    #[ignore = "Requires running database"]
    async fn test_network_stats_with_db() {
        use bitsage_node::api::dashboard::dashboard_routes;

        let state = match create_db_dashboard_state().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Skipping test: Database not available - {}", e);
                return;
            }
        };

        let app = dashboard_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/network/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: NetworkStatsResponse = serde_json::from_slice(&body).unwrap();

        // With database, should return actual data
        assert_eq!(json.network, "sepolia");
        // These values depend on database state
        println!("Total workers: {}", json.total_workers);
        println!("Total jobs: {}", json.total_jobs_processed);
        println!("✅ Network stats (with DB) test passed!");
    }

    #[tokio::test]
    #[ignore = "Requires running database"]
    async fn test_job_analytics_with_db() {
        use bitsage_node::api::dashboard::dashboard_routes;

        let state = match create_db_dashboard_state().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Skipping test: Database not available - {}", e);
                return;
            }
        };

        let app = dashboard_routes(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/jobs/analytics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: JobAnalyticsResponse = serde_json::from_slice(&body).unwrap();

        println!("Total jobs: {}", json.total_jobs);
        println!("Completed: {}", json.jobs_completed);
        println!("Success rate: {:.2}%", json.success_rate);
        println!("✅ Job analytics (with DB) test passed!");
    }
}
