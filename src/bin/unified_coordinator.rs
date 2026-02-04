//! # Unified Production Coordinator
//!
//! Single binary combining all coordinator functionality for mainnet deployment:
//! - Worker orchestration (registration, heartbeats, job assignment)
//! - Dashboard APIs (validator status, faucet, staking)
//! - Database-backed APIs (jobs, proofs, staking history, earnings)
//! - Trading/Governance/Privacy APIs
//! - WebSocket real-time updates
//! - Event indexer integration

use std::net::SocketAddr;
use std::sync::Arc;
use clap::Parser;
use tracing::{info, warn};
use anyhow::Result;
use axum::{
    Router,
    routing::{get, post},
    extract::{State, Path},
    Json,
    http::StatusCode,
};
use tower_http::cors::CorsLayer;
use tokio::signal;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

// Worker orchestration imports
use bitsage_node::coordinator::production_coordinator::{
    ProductionCoordinator,
    WorkerCapabilities,
    WorkerHeartbeat,
    JobRequest,
    JobRequirements,
};
use bitsage_node::coordinator::gpu_pricing::{
    get_gpu_pricing, calculate_job_cost, get_pricing_summary, GpuTier,
};
use bitsage_node::coordinator::supply_router::{
    SupplyRouter, SupplySource, RoutingPreference,
    RegisteredMiner, MinerStatus,
    // Job execution types
    JobSubmitRequest as SupplyJobSubmitRequest, JobResult as SupplyJobResult,
};
use bitsage_node::cloud::provider_integration::ProviderManager;
use bitsage_node::obelysk::elgamal::ECPoint;
use bitsage_node::obelysk::worker_keys::RegistrationSignature;
use chrono::Utc;

// Dashboard API imports
use bitsage_node::api::{
    dashboard_routes, DashboardApiState, DashboardContracts,
    faucet_routes, FaucetApiState,
    staking_routes, StakingApiState,
    websocket_routes, WebSocketState,
    // Database-backed APIs (DEV 1)
    jobs_db_routes, JobsDbState,
    proofs_db_routes, ProofsDbState,
    staking_db_routes, StakingDbState,
    earnings_db_routes, EarningsDbState,
    wallet_db_routes, WalletDbState,
    network_db_routes, NetworkDbState,
    dashboard_db_routes, DashboardDbState,
    // Trading/Governance/Privacy APIs (DEV 2)
    trading_routes, TradingApiState,
    governance_routes, GovernanceApiState,
    privacy_routes, PrivacyApiState,
    // Privacy Swap API
    privacy_swap_routes,
    // Worker Heartbeat API
    worker_heartbeat_routes, WorkerHeartbeatState,
    // Gasless transaction relayer
    relayer_routes, RelayerState,
    // Metrics
    metrics_routes,
    // Caching
    DashboardCache, CacheConfig, cache_cleanup_task,
};
use bitsage_node::obelysk::starknet::{FaucetClient, FaucetClientConfig};

// Indexer imports
use bitsage_node::indexer::{Indexer, IndexerConfig};

#[derive(Parser)]
#[command(name = "bitsage-coordinator")]
#[command(about = "Unified BitSage Production Coordinator")]
#[command(version)]
struct Cli {
    /// HTTP API port
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// Network (sepolia, mainnet)
    #[arg(short, long, default_value = "sepolia")]
    network: String,

    /// Starknet RPC URL
    #[arg(long, default_value = "https://starknet-sepolia-rpc.publicnode.com")]
    rpc_url: String,

    /// Database URL for PostgreSQL
    #[arg(long, default_value = "postgresql://bitsage:bitsage_dev_password@localhost:5432/sage")]
    database_url: String,

    /// Enable event indexer
    #[arg(long, default_value = "false")]
    enable_indexer: bool,

    /// Indexer poll interval in milliseconds
    #[arg(long, default_value = "3000")]
    indexer_poll_ms: u64,

    /// Start indexer from specific block (0 = latest)
    #[arg(long, default_value = "0")]
    indexer_start_block: u64,
}

/// Unified application state
#[derive(Clone)]
struct AppState {
    /// Production coordinator for worker/job management
    coordinator: Arc<ProductionCoordinator>,
    /// Supply router for hybrid cloud/miner routing
    supply_router: Arc<SupplyRouter>,
    /// WebSocket state for real-time updates
    ws_state: Arc<WebSocketState>,
    /// Database pool for persistence
    db: sqlx::PgPool,
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

    let cli = Cli::parse();

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║       BitSage Unified Production Coordinator                 ║");
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!("");
    info!("📡 Network:   {}", cli.network);
    info!("🔗 RPC:       {}", cli.rpc_url);
    info!("🗄️  Database:  {}", cli.database_url.split('@').last().unwrap_or("configured"));
    info!("📊 Indexer:   {}", if cli.enable_indexer { "enabled" } else { "disabled" });
    info!("");

    // =========================================================================
    // Database Connection
    // =========================================================================
    info!("Connecting to PostgreSQL...");
    let db_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&cli.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");
    info!("✅ Connected to PostgreSQL");

    // =========================================================================
    // Core State Initialization
    // =========================================================================

    // Production coordinator for worker management (with blockchain integration)
    let job_manager_addr = std::env::var("JOB_MANAGER_ADDRESS")
        .unwrap_or_else(|_| "0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3".to_string());
    let proof_verifier_addr = std::env::var("PROOF_VERIFIER_ADDRESS")
        .unwrap_or_else(|_| "0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b".to_string());

    let signer_pk = std::env::var("SIGNER_PRIVATE_KEY").ok().filter(|s| !s.is_empty());
    let deployer_addr = std::env::var("DEPLOYER_ADDRESS").ok().filter(|s| !s.is_empty());

    let coordinator = if let (Some(pk), Some(addr)) = (&signer_pk, &deployer_addr) {
        match ProductionCoordinator::with_blockchain_credentials(
            cli.rpc_url.clone(),
            job_manager_addr.clone(),
            proof_verifier_addr.clone(),
            pk,
            addr,
        ) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                warn!("⚠️ Blockchain+credentials init failed ({}), trying without credentials", e);
                match ProductionCoordinator::with_blockchain(
                    cli.rpc_url.clone(), job_manager_addr, proof_verifier_addr,
                ) {
                    Ok(c) => Arc::new(c),
                    Err(e2) => {
                        warn!("⚠️ Blockchain bridge init failed ({}), running without on-chain settlement", e2);
                        Arc::new(ProductionCoordinator::new())
                    }
                }
            }
        }
    } else {
        if signer_pk.is_none() {
            warn!("⚠️ SIGNER_PRIVATE_KEY not set — on-chain proof settlement disabled");
        }
        match ProductionCoordinator::with_blockchain(
            cli.rpc_url.clone(), job_manager_addr, proof_verifier_addr,
        ) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                warn!("⚠️ Blockchain bridge init failed ({}), running without on-chain settlement", e);
                Arc::new(ProductionCoordinator::new())
            }
        }
    };

    // Initialize cloud provider manager with static pricing
    let provider_manager = Arc::new(ProviderManager::new(vec![]));
    provider_manager.initialize_static_pricing().await;
    info!("✅ Cloud provider pricing initialized");

    // Supply router for hybrid cloud/miner routing
    let supply_router = Arc::new(SupplyRouter::new(provider_manager.clone()));
    info!("✅ Supply router initialized");

    // WebSocket state for real-time updates
    let ws_state = Arc::new(WebSocketState::new(2048));

    // Combined app state for worker APIs
    let app_state = AppState {
        coordinator: coordinator.clone(),
        supply_router: supply_router.clone(),
        ws_state: ws_state.clone(),
        db: db_pool.clone(),
    };

    // =========================================================================
    // Dashboard API States
    // =========================================================================

    // Initialize dashboard cache
    let dashboard_cache = Arc::new(DashboardCache::new_memory(CacheConfig::default()));
    let cache_clone = dashboard_cache.clone();
    tokio::spawn(async move {
        cache_cleanup_task(cache_clone).await;
    });

    let dashboard_state = Arc::new(DashboardApiState {
        network: cli.network.clone(),
        contracts: DashboardContracts {
            sage_token: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
            prover_staking: "0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b".to_string(),
            reputation_manager: "0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de".to_string(),
            job_manager: "0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3".to_string(),
            faucet: Some("0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3".to_string()),
        },
        metrics_aggregator: None, // Will be initialized when blockchain clients are available
        db: Some(db_pool.clone()),
        cache: Some(dashboard_cache),
    });

    // Faucet client
    let faucet_config = FaucetClientConfig {
        rpc_url: cli.rpc_url.clone(),
        enabled: true,
        claim_amount: 10_000_000_000_000_000_000, // 10 SAGE
        cooldown_secs: 86400,
        ..Default::default()
    };
    let faucet_client = Arc::new(FaucetClient::new(faucet_config).expect("Failed to create faucet client"));
    let faucet_state = Arc::new(FaucetApiState::new(faucet_client, &cli.network));

    // Staking state
    let staking_state = Arc::new(StakingApiState::disabled(&cli.network));

    // =========================================================================
    // Database-backed API States (DEV 1)
    // =========================================================================

    let jobs_db_state = JobsDbState::new(db_pool.clone());
    let proofs_db_state = ProofsDbState::new(db_pool.clone());
    let staking_db_state = StakingDbState::new(db_pool.clone());
    let earnings_db_state = EarningsDbState::new(db_pool.clone());
    let wallet_db_state = WalletDbState::new(db_pool.clone());
    let network_db_state = NetworkDbState::new(db_pool.clone());
    let dashboard_db_state = DashboardDbState::new(db_pool.clone());

    // =========================================================================
    // Trading/Governance/Privacy API States (DEV 2)
    // =========================================================================

    // Contract addresses - prefer environment variables, fallback to Sepolia defaults
    let otc_orderbook = std::env::var("OTC_ORDERBOOK_ADDRESS")
        .unwrap_or_else(|_| "0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0".to_string());
    let governance_treasury = std::env::var("GOVERNANCE_TREASURY_ADDRESS")
        .unwrap_or_else(|_| "0xdf4c3ced8c8eafe33532965fe29081e6f94fb7d54bc976721985c647a7ef92".to_string());
    let sage_token = std::env::var("SAGE_TOKEN_ADDRESS")
        .unwrap_or_else(|_| "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string());
    let privacy_router = std::env::var("PRIVACY_ROUTER_ADDRESS")
        .unwrap_or_else(|_| "0x7d1a6c242a4f0573696e117790f431fd60518a000b85fe5ee507456049ffc53".to_string());
    let privacy_pools = std::env::var("PRIVACY_POOLS_ADDRESS")
        .unwrap_or_else(|_| {
            warn!("PRIVACY_POOLS_ADDRESS not set, using placeholder 0x0 - privacy pools functionality disabled");
            "0x0".to_string()
        });

    let trading_state = Arc::new(TradingApiState::with_db(&cli.network, &otc_orderbook, db_pool.clone()));
    let governance_state = Arc::new(GovernanceApiState::new(&cli.network, &governance_treasury, &sage_token));
    let privacy_state = Arc::new(PrivacyApiState::new(&cli.network, &privacy_router, &privacy_pools));

    // =========================================================================
    // Relayer State (Gasless Transactions for Privacy Operations)
    // =========================================================================

    let paymaster_address = std::env::var("PAYMASTER_ADDRESS")
        .unwrap_or_else(|_| {
            warn!("PAYMASTER_ADDRESS not set, using placeholder - relayer functionality limited");
            "0x0".to_string()
        });

    // Chain ID for Sepolia is 0x534e5f5345504f4c4941 ("SN_SEPOLIA")
    let chain_id = if cli.network == "mainnet" {
        starknet::core::types::FieldElement::from_hex_be("0x534e5f4d41494e").unwrap() // SN_MAIN
    } else {
        starknet::core::types::FieldElement::from_hex_be("0x534e5f5345504f4c4941").unwrap() // SN_SEPOLIA
    };

    let relayer_state = RelayerState::new(
        cli.rpc_url.clone(),
        chain_id,
        starknet::core::types::FieldElement::from_hex_be(&paymaster_address).unwrap_or_default(),
        starknet::core::types::FieldElement::from_hex_be(&privacy_pools).unwrap_or_default(),
        starknet::core::types::FieldElement::from_hex_be(&privacy_router).unwrap_or_default(),
    );

    // Configure relayer with account if environment variables are set
    let relayer_state = if let (Ok(pk), Ok(addr)) = (
        std::env::var("RELAYER_PRIVATE_KEY"),
        std::env::var("RELAYER_ADDRESS")
    ) {
        info!("🔐 Relayer account configured from environment");
        relayer_state.with_relayer_account(
            starknet::core::types::FieldElement::from_hex_be(&pk).unwrap_or_default(),
            starknet::core::types::FieldElement::from_hex_be(&addr).unwrap_or_default(),
        )
    } else {
        warn!("⚠️ Relayer account not configured - gasless transactions disabled");
        relayer_state
    };

    // =========================================================================
    // Worker Heartbeat State (Uptime Tracking)
    // =========================================================================

    let worker_heartbeat_state = Arc::new(WorkerHeartbeatState {
        db: db_pool.clone(),
        ws_state: Some(ws_state.clone()),
    });

    // =========================================================================
    // Build Unified Router
    // =========================================================================

    let app = Router::new()
        // ─────────────────────────────────────────────────────────────────────
        // Core Routes
        // ─────────────────────────────────────────────────────────────────────
        .route("/", get(root_handler))
        .route("/api/health", get(health_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/network/config", get(network_config_handler))

        // ─────────────────────────────────────────────────────────────────────
        // Worker Orchestration APIs (from prod_coordinator)
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/workers/register", post(register_worker))
        .route("/api/workers/heartbeat", post(worker_heartbeat))
        .route("/api/workers/:id/status", get(worker_status))
        .route("/api/workers/:id/pubkey", get(worker_pubkey))
        .route("/api/workers/:id/poll", get(poll_for_work))
        .route("/api/workers/list", get(list_workers))

        // ─────────────────────────────────────────────────────────────────────
        // Job Management APIs (from prod_coordinator)
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/jobs/submit", post(submit_job))
        .route("/api/jobs/batch", post(submit_batch_jobs))
        .route("/api/jobs/estimate", post(estimate_job))
        .route("/api/jobs/:id/complete", post(complete_job))
        .route("/api/jobs/:id/fail", post(fail_job))
        .route("/api/jobs/:id/status", get(job_status))
        .route("/api/jobs/:id/result", get(job_result))
        // ─────────────────────────────────────────────────────────────────────
        // GPU Pricing APIs
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/pricing/gpus", get(list_gpu_pricing))
        .route("/api/pricing/summary", get(pricing_summary))
        // ─────────────────────────────────────────────────────────────────────
        // Hybrid Supply APIs (Cloud + Miners)
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/supply/stats", get(supply_stats))
        .route("/api/supply/route", post(route_job))
        .route("/api/supply/cloud/instances", get(list_cloud_instances))
        // ─────────────────────────────────────────────────────────────────────
        // Miner Registration & Mining APIs
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/miners/register", post(register_miner))
        .route("/api/miners/heartbeat", post(miner_heartbeat))
        .route("/api/miners/list", get(list_miners))
        .route("/api/miners/:id/status", get(miner_status))
        .route("/api/miners/:id/earnings", get(miner_earnings))
        .route("/api/miners/:id/poll-job", get(poll_miner_job))
        // ─────────────────────────────────────────────────────────────────────
        // Job Execution via Supply Router (Miner Mining Flow)
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/jobs/execute", post(execute_job))
        .route("/api/jobs/:id/complete-mined", post(complete_mined_job))
        .route("/api/jobs/:id/fail-mined", post(fail_mined_job))
        .route("/api/jobs/:id/miner-status", get(miner_job_status))
        .route("/api/jobs/miner-stats", get(miner_job_stats))
        // ─────────────────────────────────────────────────────────────────────
        // Model Deployment APIs (one-liner model deployment)
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/models/deploy", post(deploy_model))
        .route("/api/models/:id/inference", post(model_inference))
        .route("/api/models/:id/status", get(model_status))
        .route("/api/models/list", get(list_models))
        // ─────────────────────────────────────────────────────────────────────
        // Model Training APIs
        // ─────────────────────────────────────────────────────────────────────
        .route("/api/training/submit", post(submit_training_job))
        .route("/api/training/:id/status", get(training_job_status))
        .route("/api/training/:id/cancel", post(cancel_training_job))
        .route("/api/training/:id/checkpoints", get(list_training_checkpoints))
        .route("/api/rl/submit", post(submit_rl_training_job))

        .with_state(app_state)

        // ─────────────────────────────────────────────────────────────────────
        // Dashboard APIs (from simple_coordinator)
        // ─────────────────────────────────────────────────────────────────────
        .merge(dashboard_routes(dashboard_state))
        .merge(faucet_routes(faucet_state))
        .merge(staking_routes(staking_state))
        .merge(websocket_routes(ws_state.clone()))

        // ─────────────────────────────────────────────────────────────────────
        // Database-backed APIs (DEV 1)
        // ─────────────────────────────────────────────────────────────────────
        .merge(jobs_db_routes(jobs_db_state))
        .merge(proofs_db_routes(proofs_db_state))
        .merge(staking_db_routes(staking_db_state))
        .merge(earnings_db_routes(earnings_db_state))
        .merge(wallet_db_routes(wallet_db_state))
        .merge(network_db_routes(network_db_state))
        .merge(dashboard_db_routes(dashboard_db_state))

        // ─────────────────────────────────────────────────────────────────────
        // Worker Heartbeat/Uptime APIs
        // ─────────────────────────────────────────────────────────────────────
        .merge(worker_heartbeat_routes(worker_heartbeat_state))

        // ─────────────────────────────────────────────────────────────────────
        // Trading/Governance/Privacy APIs (DEV 2)
        // ─────────────────────────────────────────────────────────────────────
        .merge(trading_routes(trading_state))
        .merge(governance_routes(governance_state))
        .merge(privacy_routes(privacy_state))
        // Privacy Swap API (simplified - no matching engine)
        .merge(privacy_swap_routes().0)

        // ─────────────────────────────────────────────────────────────────────
        // Gasless Transaction Relayer (for Privacy Operations)
        // ─────────────────────────────────────────────────────────────────────
        .merge(relayer_routes(relayer_state))

        // ─────────────────────────────────────────────────────────────────────
        // Prometheus Metrics & Health
        // ─────────────────────────────────────────────────────────────────────
        .merge(metrics_routes())

        .layer(CorsLayer::permissive());

    // =========================================================================
    // Start Event Indexer (Optional)
    // =========================================================================

    if cli.enable_indexer {
        let indexer_config = IndexerConfig {
            enabled: true,
            rpc_url: cli.rpc_url.clone(),
            poll_interval_ms: cli.indexer_poll_ms,
            batch_size: 100,
            start_block: cli.indexer_start_block,
            max_retries: 5,
            database_url: cli.database_url.clone(),
        };

        let ws_state_clone = ws_state.clone();

        tokio::spawn(async move {
            info!("🔍 Starting event indexer...");
            match Indexer::new_with_websocket(indexer_config, ws_state_clone).await {
                Ok(mut indexer) => {
                    if let Err(e) = indexer.start().await {
                        warn!("Indexer error: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to create indexer: {}", e);
                }
            }
        });
    }

    // =========================================================================
    // Network Stats Broadcasting Task
    // =========================================================================

    let stats_ws_state = ws_state.clone();
    let stats_db = db_pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;

            // Query network stats from database
            let stats = sqlx::query(
                r#"
                SELECT
                    (SELECT COUNT(DISTINCT worker_address) FROM jobs WHERE worker_address IS NOT NULL)::int as total_workers,
                    (SELECT COUNT(DISTINCT worker_address) FROM jobs WHERE status IN ('running', 'pending') AND created_at > NOW() - INTERVAL '5 minutes')::int as active_workers,
                    (SELECT COUNT(*) FROM jobs)::bigint as total_jobs,
                    (SELECT COUNT(*) FROM jobs WHERE status IN ('running', 'pending'))::int as jobs_in_progress,
                    (SELECT COUNT(*) FROM jobs WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '24 hours')::bigint as jobs_24h,
                    (SELECT COUNT(*) FROM jobs WHERE completed_at > NOW() - INTERVAL '1 minute')::float / 60.0 as network_tps
                "#
            )
            .fetch_one(&stats_db)
            .await;

            if let Ok(row) = stats {
                use sqlx::Row;
                stats_ws_state.broadcast_network_stats(
                    row.try_get::<i32, _>("total_workers").unwrap_or(0) as u32,
                    row.try_get::<i32, _>("active_workers").unwrap_or(0) as u32,
                    row.try_get::<i64, _>("total_jobs").unwrap_or(0) as u64,
                    row.try_get::<i32, _>("jobs_in_progress").unwrap_or(0) as u32,
                    row.try_get::<i64, _>("jobs_24h").unwrap_or(0) as u64,
                    row.try_get::<f64, _>("network_tps").unwrap_or(0.0) as f32,
                );
            }
        }
    });

    // =========================================================================
    // Start HTTP Server
    // =========================================================================

    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;
    info!("🌐 Starting HTTP server on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("");
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  ✅ Unified Coordinator is RUNNING                           ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  🔧 Worker APIs:                                             ║");
    info!("║     POST /api/workers/register                               ║");
    info!("║     POST /api/workers/heartbeat                              ║");
    info!("║     GET  /api/workers/:id/poll                               ║");
    info!("║     POST /api/jobs/submit                                    ║");
    info!("║                                                              ║");
    info!("║  ⛏️  Miner Mining APIs (SAGE Rewards):                        ║");
    info!("║     POST /api/miners/register                                ║");
    info!("║     POST /api/jobs/execute      (submit → route → assign)    ║");
    info!("║     GET  /api/miners/:id/poll-job  (get assigned job)        ║");
    info!("║     POST /api/jobs/:id/complete-mined  (submit result)       ║");
    info!("║     GET  /api/jobs/miner-stats                               ║");
    info!("║                                                              ║");
    info!("║  📊 Dashboard APIs:                                          ║");
    info!("║     GET  /api/validator/status                               ║");
    info!("║     GET  /api/faucet/config                                  ║");
    info!("║     GET  /api/staking/config                                 ║");
    info!("║                                                              ║");
    info!("║  🗄️  Database APIs:                                           ║");
    info!("║     GET  /api/jobs/db                                        ║");
    info!("║     GET  /api/proofs                                         ║");
    info!("║     GET  /api/staking/db/stats                               ║");
    info!("║     GET  /api/earnings/network/stats                         ║");
    info!("║                                                              ║");
    info!("║  💹 Trading/Governance:                                      ║");
    info!("║     GET  /api/trading/pairs                                  ║");
    info!("║     GET  /api/governance/proposals                           ║");
    info!("║     GET  /api/privacy/stats                                  ║");
    info!("║                                                              ║");
    info!("║  🔒 Gasless Relayer (Privacy):                               ║");
    info!("║     POST /api/relay/submit                                   ║");
    info!("║     POST /api/relay/quote                                    ║");
    info!("║     GET  /api/relay/allowance/:address                       ║");
    info!("║     GET  /api/relay/health                                   ║");
    info!("║                                                              ║");
    info!("║  🔌 WebSocket:                                               ║");
    info!("║     ws://{}/ws                                   ║", addr);
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!("");
    info!("Press Ctrl+C to shutdown...");

    // Run with graceful shutdown
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("✅ Coordinator stopped cleanly");
    Ok(())
}

// =============================================================================
// Core Handlers
// =============================================================================

async fn root_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "BitSage Unified Production Coordinator",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "online",
        "capabilities": [
            "worker-orchestration",
            "multi-gpu-scheduling",
            "tee-awareness",
            "database-backed-apis",
            "real-time-websocket",
            "event-indexing",
            "trading",
            "governance",
            "privacy"
        ]
    }))
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp()
    }))
}

async fn stats_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = state.coordinator.get_stats().await;
    let ws_subscribers = state.ws_state.subscriber_count();

    Json(serde_json::json!({
        "coordinator": stats,
        "websocket_subscribers": ws_subscribers
    }))
}

/// Network configuration endpoint — workers fetch this on startup
/// instead of requiring local .env configuration for contract addresses.
async fn network_config_handler() -> Json<serde_json::Value> {
    let paymaster_address = std::env::var("PAYMASTER_ADDRESS")
        .unwrap_or_default();
    let proof_verifier = std::env::var("PROOF_VERIFIER_ADDRESS")
        .unwrap_or_default();
    let stwo_verifier = std::env::var("STWO_VERIFIER_ADDRESS")
        .unwrap_or_default();
    let staking_contract = std::env::var("STAKING_CONTRACT_ADDRESS")
        .unwrap_or_default();
    let sage_token = std::env::var("SAGE_TOKEN_ADDRESS")
        .unwrap_or_default();
    let starknet_rpc = std::env::var("STARKNET_RPC_URL")
        .unwrap_or_default();
    let network = std::env::var("STARKNET_NETWORK")
        .unwrap_or_else(|_| "sepolia".to_string());

    let vllm_endpoint = std::env::var("VLLM_ENDPOINT")
        .unwrap_or_default();

    Json(serde_json::json!({
        "network": network,
        "rpc_url": starknet_rpc,
        "paymaster_address": paymaster_address,
        "proof_verifier_address": proof_verifier,
        "stwo_verifier_address": stwo_verifier,
        "staking_contract_address": staking_contract,
        "sage_token_address": sage_token,
        "vllm_endpoint": vllm_endpoint,
    }))
}

// =============================================================================
// Worker Orchestration Handlers
// =============================================================================

#[derive(Debug, Deserialize)]
struct RegisterWorkerRequest {
    worker_id: String,
    capabilities: WorkerCapabilities,
    #[serde(default)]
    wallet_address: Option<String>,
    #[serde(default)]
    privacy_public_key: Option<ECPoint>,
    #[serde(default)]
    privacy_key_signature: Option<RegistrationSignature>,
    /// X25519 public key for E2E encrypted job communication
    #[serde(default)]
    encryption_pubkey: Option<[u8; 32]>,
}

async fn register_worker(
    State(state): State<AppState>,
    Json(req): Json<RegisterWorkerRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.coordinator
        .register_worker_with_privacy(
            req.worker_id.clone(),
            req.capabilities,
            req.wallet_address,
            req.privacy_public_key,
            req.privacy_key_signature,
            req.encryption_pubkey,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "registered",
        "worker_id": req.worker_id
    })))
}

async fn worker_heartbeat(
    State(state): State<AppState>,
    Json(heartbeat): Json<WorkerHeartbeat>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let worker_id = heartbeat.worker_id.clone();
    let current_load = heartbeat.current_load;

    // Update in-memory coordinator state
    state.coordinator
        .update_worker_heartbeat(heartbeat)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Also persist to database for dashboard tracking
    let _ = sqlx::query(
        r#"
        INSERT INTO heartbeats (worker_address, gpu_count, gpu_utilization, memory_utilization, jobs_in_progress)
        VALUES ($1, 0, $2, $2, 0)
        ON CONFLICT (worker_address, heartbeat_time) DO UPDATE SET
            gpu_utilization = EXCLUDED.gpu_utilization,
            memory_utilization = EXCLUDED.memory_utilization
        "#
    )
    .bind(&worker_id)
    .bind(current_load * 100.0) // Convert load to percentage
    .execute(&state.db)
    .await;

    // Broadcast to WebSocket subscribers
    state.ws_state.broadcast_worker_update(
        worker_id.clone(),
        "online".to_string(),
        None,
        Some(current_load * 100.0),
    );

    Ok(Json(serde_json::json!({
        "status": "ok",
        "worker_id": worker_id
    })))
}

async fn worker_status(
    State(state): State<AppState>,
    Path(worker_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.coordinator.get_worker_status(&worker_id).await {
        Some(status) => Ok(Json(serde_json::json!({
            "worker_id": worker_id,
            "status": format!("{:?}", status)
        }))),
        None => Err((StatusCode::NOT_FOUND, "Worker not found".to_string()))
    }
}

/// Get a worker's X25519 encryption public key (for clients to encrypt job payloads)
async fn worker_pubkey(
    State(state): State<AppState>,
    Path(worker_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.coordinator.get_worker_encryption_pubkey(&worker_id).await {
        Some(pubkey) => Ok(Json(serde_json::json!({
            "worker_id": worker_id,
            "encryption_pubkey": hex::encode(pubkey),
            "key_type": "X25519",
        }))),
        None => Err((StatusCode::NOT_FOUND, format!("Worker {} not found or has no encryption key", worker_id)))
    }
}

async fn poll_for_work(
    State(state): State<AppState>,
    Path(worker_id): Path<String>,
) -> Json<serde_json::Value> {
    match state.coordinator.poll_for_work(worker_id).await {
        Some(job) => Json(serde_json::to_value(job).unwrap()),
        None => Json(serde_json::json!(null))
    }
}

async fn list_workers(State(state): State<AppState>) -> Json<serde_json::Value> {
    let workers = state.coordinator.list_workers().await;
    Json(serde_json::json!({
        "workers": workers.iter().map(|(id, status, load)| {
            serde_json::json!({
                "id": id,
                "status": format!("{:?}", status),
                "load": load
            })
        }).collect::<Vec<_>>()
    }))
}

// =============================================================================
// Job Management Handlers
// =============================================================================

async fn submit_job(
    State(state): State<AppState>,
    Json(req): Json<JobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let job_id = state.coordinator
        .submit_job(req)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "submitted",
        "job_id": job_id
    })))
}

#[derive(Debug, Deserialize)]
struct CompleteJobRequest {
    result: Vec<u8>,
    #[serde(default)]
    tee_attestation: Option<String>,
    #[serde(default)]
    proof_hash: Option<String>,
    #[serde(default)]
    proof_commitment: Option<String>,
    #[serde(default)]
    proof_size_bytes: Option<usize>,
}

async fn complete_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(req): Json<CompleteJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Use proof-aware completion path
    let tee_bytes = req.tee_attestation.map(|s| s.into_bytes());
    state.coordinator
        .complete_job_with_proof(
            job_id, req.result, tee_bytes,
            req.proof_hash, req.proof_commitment, req.proof_size_bytes,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "completed"})))
}

#[derive(Debug, Deserialize)]
struct FailJobRequest {
    error: String,
}

async fn fail_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(req): Json<FailJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.coordinator
        .fail_job(job_id, req.error)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "failed"})))
}

async fn job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.coordinator.get_job_status(&job_id).await {
        Some(status) => {
            let mut response = serde_json::json!({
                "job_id": job_id,
                "status": format!("{:?}", status),
            });

            // If completed, include result metadata
            if matches!(status, bitsage_node::coordinator::production_coordinator::JobStatus::Completed) {
                if let Some((result, tee_att, is_encrypted)) = state.coordinator.get_job_result_with_metadata(&job_id).await {
                    if let Some(obj) = response.as_object_mut() {
                        obj.insert("result_size_bytes".to_string(), serde_json::json!(result.len()));
                        obj.insert("encrypted".to_string(), serde_json::json!(is_encrypted));
                        obj.insert("has_tee_attestation".to_string(), serde_json::json!(tee_att.is_some()));
                        obj.insert("result_endpoint".to_string(),
                            serde_json::json!(format!("/api/jobs/{}/result", job_id)));
                    }
                }
            }

            Ok(Json(response))
        }
        None => Err((StatusCode::NOT_FOUND, "Job not found".to_string()))
    }
}

/// Get job result (returns raw bytes — encrypted if customer_pubkey was set)
async fn job_result(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.coordinator.get_job_result_with_metadata(&job_id).await {
        Some((result, tee_attestation, is_encrypted)) => {
            // Hex-encode binary data for JSON transport
            let result_hex = hex::encode(&result);
            let tee_hex = tee_attestation.as_ref().map(|a| hex::encode(a));
            Ok(Json(serde_json::json!({
                "job_id": job_id,
                "encrypted": is_encrypted,
                "result_hex": result_hex,
                "tee_attestation_hex": tee_hex,
                "result_size_bytes": result.len(),
            })))
        }
        None => Err((StatusCode::NOT_FOUND, "Job result not found".to_string()))
    }
}

// =============================================================================
// Job Estimation Handler
// =============================================================================

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct EstimateJobRequest {
    job_type: String,
    payload_size_bytes: Option<u64>,
    requirements: Option<JobRequirements>,
}

async fn estimate_job(
    State(state): State<AppState>,
    Json(req): Json<EstimateJobRequest>,
) -> Json<serde_json::Value> {
    // =========================================================================
    // BITSAGE PRICING MODEL (from Financial Model v2)
    // =========================================================================
    //
    // PRICING: In USD (real-world anchor based on GPU-hours)
    // Uses centralized gpu_pricing module with 40+ GPU models
    //
    // Fee Split (80/20):
    //   - 80% → Worker payment
    //   - 20% → Protocol fee
    //       - 70% of protocol fee → Burn (deflationary)
    //       - 20% of protocol fee → Treasury (ops)
    //       - 10% of protocol fee → Stakers (real yield)
    // =========================================================================

    // Determine GPU model from requirements
    let gpu_model = req.requirements.as_ref()
        .and_then(|r| {
            // Map VRAM requirements to GPU model
            if r.min_vram_mb >= 80000 { Some("H100_SXM") }
            else if r.min_vram_mb >= 48000 { Some("A100_SXM_80GB") }
            else if r.min_vram_mb >= 24000 { Some("RTX_4090") }
            else if r.min_vram_mb >= 16000 { Some("RTX_4080") }
            else { Some("RTX_4070") }
        })
        .unwrap_or("RTX_4090");

    // Get GPU pricing data
    let gpus = get_gpu_pricing();
    let gpu_info = gpus.get(gpu_model).cloned();

    let (gpu_rate_cents, gpu_name, gpu_tier) = gpu_info
        .map(|g| (g.bitsage_rate_cents as u64, g.name, g.tier))
        .unwrap_or((35, "NVIDIA RTX 4090", GpuTier::Consumer));

    // Estimate GPU-seconds based on job type
    let (gpu_seconds, cpu_seconds, requires_gpu) = match req.job_type.as_str() {
        // AI/ML - GPU intensive
        "AIInference" => (30, 5, true),
        "ModelInference" => (10, 2, true),
        "BatchInference" => (60, 10, true),
        "ModelDeploy" => (120, 30, true),

        // ZK Proofs - GPU intensive
        "STWOProof" | "ZKProof" | "ObelyskProof" => (45, 10, true),

        // Data Processing - CPU mostly
        "DataPipeline" => (0, 60, false),

        // Confidential - Premium
        "ConfidentialVM" => (60, 30, true),
        "FHECompute" => (300, 60, true),
        "ConfidentialAI" => (600, 120, true),

        // Rendering - GPU intensive
        "Render3D" => (180, 30, true),
        "VideoProcessing" => (120, 20, true),

        // Training workloads — GPU-hours
        "ModelTraining" | "AITraining" | "FineTune" => (3600, 60, true),
        "LoRA" => (1800, 30, true),
        "ReinforcementLearning" | "RLHF" | "DPO" => (7200, 120, true),

        // Light workloads
        "ComputerVision" => (5, 2, true),
        "NLP" => (3, 1, true),

        _ => (10, 5, false),
    };

    // Use centralized cost calculation if GPU model found
    let cost_breakdown = calculate_job_cost(gpu_model, gpu_seconds);

    // Fallback calculation if no cost breakdown
    let (total_cost_cents, worker_cents, protocol_fee_cents, burn_cents, treasury_cents, staker_cents) =
        cost_breakdown.as_ref().map(|c| {
            (c.total_cents, c.worker_payment_cents, c.protocol_fee_cents,
             c.burn_cents, c.treasury_cents, c.staker_cents)
        }).unwrap_or_else(|| {
            // Manual calculation
            let gpu_cost = (gpu_seconds * gpu_rate_cents) / 3600;
            let cpu_cost = (cpu_seconds * 5) / 3600;
            let total = std::cmp::max(gpu_cost + cpu_cost, 1);
            let worker = total * 80 / 100;
            let protocol = total - worker;
            let burn = protocol * 70 / 100;
            let treasury = protocol * 20 / 100;
            let staker = protocol - burn - treasury;
            (total, worker, protocol, burn, treasury, staker)
        });

    // Convert to dollars
    let total_cost_usd = total_cost_cents as f64 / 100.0;
    let worker_payment_usd = worker_cents as f64 / 100.0;
    let protocol_fee_usd = protocol_fee_cents as f64 / 100.0;
    let burn_usd = burn_cents as f64 / 100.0;
    let treasury_usd = treasury_cents as f64 / 100.0;
    let staker_yield_usd = staker_cents as f64 / 100.0;

    // Convert to SAGE at current rate (TODO: get from oracle)
    let sage_price_usd = 0.10;
    let total_cost_sage = total_cost_usd / sage_price_usd;
    let worker_payment_sage = worker_payment_usd / sage_price_usd;

    // Mining reward (SAGE emissions during bootstrap)
    let mining_base = 0.001;
    let difficulty_multiplier = (gpu_seconds as f64).log2() / 20.0;
    let mining_reward_sage = mining_base * difficulty_multiplier.max(0.1);

    // Check worker availability
    let stats = state.coordinator.get_stats().await;
    let workers_available = stats.online_workers > 0;
    let queue_time_ms = if stats.online_workers > 0 {
        (stats.pending_jobs as u64 * 100) / stats.online_workers as u64
    } else {
        0
    };

    Json(serde_json::json!({
        "job_type": req.job_type,
        "pricing_model": "market_competitive_usd",

        // Resource breakdown
        "resources": {
            "gpu_seconds": gpu_seconds,
            "cpu_seconds": cpu_seconds,
            "gpu_model": gpu_model,
            "gpu_name": gpu_name,
            "gpu_tier": format!("{:?}", gpu_tier),
            "gpu_rate_per_hour_usd": format!("${:.2}", gpu_rate_cents as f64 / 100.0),
        },

        // Cost in USD (market-based anchor)
        "cost_usd": {
            "total": format!("${:.4}", total_cost_usd),
            "worker_payment_80pct": format!("${:.4}", worker_payment_usd),
            "protocol_fee_20pct": format!("${:.4}", protocol_fee_usd),
        },

        // Protocol fee breakdown (20% of total)
        "fee_breakdown_usd": {
            "burn_70pct": format!("${:.4}", burn_usd),
            "treasury_20pct": format!("${:.4}", treasury_usd),
            "staker_yield_10pct": format!("${:.4}", staker_yield_usd),
        },

        // SAGE equivalent (at current rate)
        "sage_equivalent": {
            "sage_price_usd": sage_price_usd,
            "total_cost_sage": format!("{:.4}", total_cost_sage),
            "worker_payment_sage": format!("{:.4}", worker_payment_sage),
        },

        // Mining rewards (bootstrap phase)
        "mining": {
            "phase": "bootstrap",
            "mining_reward_sage": format!("{:.6}", mining_reward_sage),
            "note": "Workers earn SAGE from emissions for completing jobs",
        },

        // Time estimates
        "time_estimates": {
            "execution_time_seconds": gpu_seconds + cpu_seconds,
            "queue_time_ms": queue_time_ms,
        },

        // Requirements
        "requirements": {
            "gpu_required": requires_gpu,
            "min_gpu_tier": format!("{:?}", gpu_tier),
        },

        // Network status
        "network": {
            "workers_available": workers_available,
            "online_workers": stats.online_workers,
            "pending_jobs": stats.pending_jobs,
        },

        // Payment acceptance
        "payment": {
            "accepts_sage": true,
            "accepts_usdc": true,
            "accepts_strk": true,
            "sage_discount_pct": 20,
        },
    }))
}

// =============================================================================
// Batch Job Submission Handler
// =============================================================================

#[derive(Debug, Deserialize)]
struct BatchJobRequest {
    jobs: Vec<JobRequest>,
}

async fn submit_batch_jobs(
    State(state): State<AppState>,
    Json(req): Json<BatchJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut job_ids = Vec::new();
    let mut errors = Vec::new();

    for (idx, job) in req.jobs.into_iter().enumerate() {
        match state.coordinator.submit_job(job).await {
            Ok(job_id) => job_ids.push(job_id),
            Err(e) => errors.push(serde_json::json!({
                "index": idx,
                "error": e.to_string()
            })),
        }
    }

    Ok(Json(serde_json::json!({
        "status": if errors.is_empty() { "all_submitted" } else { "partial_success" },
        "job_ids": job_ids,
        "submitted_count": job_ids.len(),
        "errors": errors,
        "failed_count": errors.len(),
    })))
}

// =============================================================================
// Model Deployment Handlers
// =============================================================================

#[derive(Debug, Deserialize)]
struct ModelDeployApiRequest {
    model_name: String,
    #[serde(default = "default_huggingface")]
    source: String,
    #[serde(default = "default_medium")]
    model_size: String,
    #[serde(default = "default_fp16")]
    quantization: String,
}

fn default_huggingface() -> String { "huggingface".to_string() }
fn default_medium() -> String { "medium".to_string() }
fn default_fp16() -> String { "fp16".to_string() }

async fn deploy_model(
    State(state): State<AppState>,
    Json(req): Json<ModelDeployApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Create a job request for model deployment
    let payload = serde_json::to_vec(&serde_json::json!({
        "model_name": req.model_name,
        "source": req.source,
        "model_size": req.model_size,
        "quantization": req.quantization,
    })).unwrap_or_default();

    let job_req = JobRequest {
        id: None,
        requirements: JobRequirements {
            min_vram_mb: match req.model_size.as_str() {
                "small" => 4096,
                "medium" => 16384,
                "large" => 40960,
                "xlarge" => 81920,
                _ => 8192,
            },
            min_gpu_count: 1,
            required_job_type: "ModelDeploy".to_string(),
            timeout_seconds: 600,
            requires_tee: false,
        },
        payload,
        priority: 100, // High priority for deployment
        customer_pubkey: None,
    };

    let job_id = state.coordinator
        .submit_job(job_req)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "deploying",
        "job_id": job_id,
        "model_name": req.model_name,
        "message": format!("Model deployment job submitted. Poll /api/jobs/{}/status for updates.", job_id),
        "inference_endpoint": format!("/api/models/{}/inference", job_id),
    })))
}

#[derive(Debug, Deserialize)]
struct ModelInferenceApiRequest {
    input: serde_json::Value,
    #[serde(default = "default_llm")]
    model_type: String,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
    /// Customer's X25519 public key for E2E encrypted results
    #[serde(default)]
    customer_pubkey: Option<[u8; 32]>,
}

fn default_llm() -> String { "llm".to_string() }

async fn model_inference(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
    Json(req): Json<ModelInferenceApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Create an inference job
    let requires_tee = req.customer_pubkey.is_some();
    let payload = serde_json::to_vec(&serde_json::json!({
        "model_id": model_id,
        "model_type": req.model_type,
        "input": req.input,
        "max_tokens": req.max_tokens,
        "temperature": req.temperature,
        "customer_pubkey": req.customer_pubkey,
    })).unwrap_or_default();

    let job_req = JobRequest {
        id: None,
        requirements: JobRequirements {
            min_vram_mb: 8192,
            min_gpu_count: 1,
            required_job_type: "ModelInference".to_string(),
            timeout_seconds: 120,
            requires_tee,
        },
        payload,
        priority: 150, // High priority for inference
        customer_pubkey: req.customer_pubkey,
    };

    let job_id = state.coordinator
        .submit_job(job_req)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "processing",
        "job_id": job_id,
        "model_id": model_id,
        "message": format!("Inference job submitted. Poll /api/jobs/{}/status for results.", job_id),
    })))
}

async fn model_status(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Check if there's a deployment job for this model
    match state.coordinator.get_job_status(&model_id).await {
        Some(status) => Ok(Json(serde_json::json!({
            "model_id": model_id,
            "status": format!("{:?}", status),
            "inference_endpoint": format!("/api/models/{}/inference", model_id),
        }))),
        None => Err((StatusCode::NOT_FOUND, format!("Model {} not found", model_id)))
    }
}

async fn list_models(
    State(_state): State<AppState>,
) -> Json<serde_json::Value> {
    // Return list of available models (could be stored in DB)
    Json(serde_json::json!({
        "models": [
            {
                "name": "meta-llama/Llama-3.1-8B",
                "type": "llm",
                "size": "medium",
                "status": "available"
            },
            {
                "name": "stabilityai/stable-diffusion-xl-base-1.0",
                "type": "image_gen",
                "size": "large",
                "status": "available"
            },
            {
                "name": "sentence-transformers/all-MiniLM-L6-v2",
                "type": "embedding",
                "size": "small",
                "status": "available"
            },
            {
                "name": "ultralytics/yolov8n",
                "type": "object_detection",
                "size": "small",
                "status": "available"
            }
        ],
        "supported_sources": ["huggingface", "s3", "ipfs", "url"],
        "supported_quantizations": ["fp16", "int8", "int4", "none"]
    }))
}

// =============================================================================
// Model Training Handlers
// =============================================================================

#[derive(Debug, Deserialize)]
struct TrainingJobApiRequest {
    /// Base model (e.g. "meta-llama/Llama-3.1-8B")
    base_model: String,
    /// "full", "lora", "qlora", "freeze_layers"
    #[serde(default = "default_lora_mode")]
    training_mode: String,
    /// S3, local, or HuggingFace dataset path
    dataset_path: String,
    /// Dataset format: "jsonl", "parquet", "csv", "hf_dataset"
    #[serde(default = "default_jsonl_fmt")]
    dataset_format: String,
    /// Output directory for checkpoints
    #[serde(default = "default_output_path")]
    output_path: String,
    /// Framework: "huggingface", "deepspeed", "pytorch"
    #[serde(default = "default_huggingface")]
    framework: String,
    /// Number of GPUs
    #[serde(default = "default_one")]
    num_gpus: u32,
    /// Learning rate
    #[serde(default = "default_lr")]
    learning_rate: f64,
    /// Batch size
    #[serde(default = "default_batch_4")]
    batch_size: u32,
    /// Number of epochs
    #[serde(default = "default_epochs")]
    num_epochs: u32,
    /// Max training steps (0 = use epochs)
    #[serde(default)]
    max_steps: u64,
    /// LoRA rank (for lora/qlora modes)
    #[serde(default = "default_lora_rank")]
    lora_rank: u32,
    /// LoRA alpha
    #[serde(default = "default_lora_alpha")]
    lora_alpha: f32,
    /// Evaluation dataset path (optional)
    eval_dataset_path: Option<String>,
}

fn default_lora_mode() -> String { "lora".to_string() }
fn default_jsonl_fmt() -> String { "jsonl".to_string() }
fn default_output_path() -> String { "/outputs/training".to_string() }
fn default_one() -> u32 { 1 }
fn default_lr() -> f64 { 2e-5 }
fn default_batch_4() -> u32 { 4 }
fn default_epochs() -> u32 { 3 }
fn default_lora_rank() -> u32 { 16 }
fn default_lora_alpha() -> f32 { 32.0 }

async fn submit_training_job(
    State(state): State<AppState>,
    Json(req): Json<TrainingJobApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "base_model": req.base_model,
        "training_mode": req.training_mode,
        "dataset_path": req.dataset_path,
        "dataset_format": req.dataset_format,
        "output_path": req.output_path,
        "framework": req.framework,
        "num_gpus": req.num_gpus,
        "hyperparameters": {
            "learning_rate": req.learning_rate,
            "per_device_train_batch_size": req.batch_size,
            "num_train_epochs": req.num_epochs,
            "max_steps": req.max_steps,
        },
        "lora_config": if req.training_mode == "lora" || req.training_mode == "qlora" {
            Some(serde_json::json!({
                "rank": req.lora_rank,
                "alpha": req.lora_alpha,
                "use_qlora": req.training_mode == "qlora",
            }))
        } else {
            None
        },
        "eval_dataset_path": req.eval_dataset_path,
    })).unwrap_or_default();

    let vram_required = match req.training_mode.as_str() {
        "qlora" => 16384,
        "lora" => 24576,
        "freeze_layers" => 40960,
        _ => 81920, // full training needs max VRAM
    };

    let job_type = match req.training_mode.as_str() {
        "lora" | "qlora" => "LoRA",
        _ => "ModelTraining",
    };

    let job_req = JobRequest {
        id: None,
        requirements: JobRequirements {
            min_vram_mb: vram_required,
            min_gpu_count: req.num_gpus as u8,
            required_job_type: job_type.to_string(),
            timeout_seconds: 86400, // 24h max for training
            requires_tee: false,
        },
        payload,
        priority: 50, // Lower priority than inference
        customer_pubkey: None,
    };

    let job_id = state.coordinator
        .submit_job(job_req)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "training_submitted",
        "job_id": job_id,
        "base_model": req.base_model,
        "training_mode": req.training_mode,
        "framework": req.framework,
        "num_gpus": req.num_gpus,
        "estimated_vram_mb": vram_required,
        "status_endpoint": format!("/api/training/{}/status", job_id),
        "checkpoints_endpoint": format!("/api/training/{}/checkpoints", job_id),
    })))
}

#[derive(Debug, Deserialize)]
struct RLTrainingApiRequest {
    /// Base model to align
    base_model: String,
    /// Algorithm: "dpo", "ppo", "rlhf", "grpo"
    #[serde(default = "default_dpo")]
    algorithm: String,
    /// Dataset path (preference pairs for DPO, prompts for PPO)
    dataset_path: String,
    /// Output directory
    #[serde(default = "default_output_path")]
    output_path: String,
    /// Training steps
    #[serde(default = "default_rl_steps")]
    training_steps: u64,
    /// Learning rate
    #[serde(default = "default_lr")]
    learning_rate: f64,
    /// Beta for DPO
    #[serde(default = "default_beta")]
    beta: f64,
    /// Number of GPUs
    #[serde(default = "default_one")]
    num_gpus: u32,
}

fn default_dpo() -> String { "dpo".to_string() }
fn default_rl_steps() -> u64 { 1000 }
fn default_beta() -> f64 { 0.1 }

async fn submit_rl_training_job(
    State(state): State<AppState>,
    Json(req): Json<RLTrainingApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "base_model": req.base_model,
        "algorithm": req.algorithm,
        "dataset_path": req.dataset_path,
        "output_path": req.output_path,
        "training_steps": req.training_steps,
        "learning_rate": req.learning_rate,
        "beta": req.beta,
        "num_gpus": req.num_gpus,
    })).unwrap_or_default();

    let job_type = match req.algorithm.as_str() {
        "dpo" => "DPO",
        "ppo" | "rlhf" => "RLHF",
        _ => "ReinforcementLearning",
    };

    let job_req = JobRequest {
        id: None,
        requirements: JobRequirements {
            min_vram_mb: 40960,
            min_gpu_count: req.num_gpus as u8,
            required_job_type: job_type.to_string(),
            timeout_seconds: 86400,
            requires_tee: false,
        },
        payload,
        priority: 50,
        customer_pubkey: None,
    };

    let job_id = state.coordinator
        .submit_job(job_req)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "rl_training_submitted",
        "job_id": job_id,
        "base_model": req.base_model,
        "algorithm": req.algorithm,
        "training_steps": req.training_steps,
        "status_endpoint": format!("/api/training/{}/status", job_id),
    })))
}

async fn training_job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.coordinator.get_job_status(&job_id).await {
        Some(status) => {
            let result = state.coordinator.get_job_result(&job_id).await;
            let mut response = serde_json::json!({
                "job_id": job_id,
                "status": format!("{:?}", status),
            });

            // If completed, parse training metrics from result
            if let Some(result_bytes) = result {
                if let Ok(result_str) = String::from_utf8(result_bytes) {
                    if let Ok(metrics) = serde_json::from_str::<serde_json::Value>(&result_str) {
                        response["result"] = metrics;
                    } else {
                        response["result_raw"] = serde_json::Value::String(result_str);
                    }
                }
            }

            Ok(Json(response))
        }
        None => Err((StatusCode::NOT_FOUND, format!("Training job {} not found", job_id)))
    }
}

async fn cancel_training_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.coordinator
        .fail_job(job_id.clone(), "Cancelled by user".to_string())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "cancelled",
        "job_id": job_id,
    })))
}

async fn list_training_checkpoints(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Verify job exists
    match state.coordinator.get_job_status(&job_id).await {
        Some(status) => {
            let result = state.coordinator.get_job_result(&job_id).await;
            let mut checkpoints = Vec::new();

            if let Some(result_bytes) = result {
                if let Ok(result_str) = String::from_utf8(result_bytes) {
                    if let Ok(metrics) = serde_json::from_str::<serde_json::Value>(&result_str) {
                        if let Some(cp_list) = metrics.get("checkpoints").and_then(|v| v.as_array()) {
                            checkpoints = cp_list.clone();
                        }
                    }
                }
            }

            Ok(Json(serde_json::json!({
                "job_id": job_id,
                "status": format!("{:?}", status),
                "checkpoints": checkpoints,
            })))
        }
        None => Err((StatusCode::NOT_FOUND, format!("Training job {} not found", job_id)))
    }
}

// =============================================================================
// GPU Pricing Handlers
// =============================================================================

async fn list_gpu_pricing() -> Json<serde_json::Value> {
    let gpus = get_gpu_pricing();

    // Group GPUs by tier
    let mut consumer = Vec::new();
    let mut professional = Vec::new();
    let mut datacenter = Vec::new();
    let mut enterprise = Vec::new();
    let mut frontier = Vec::new();

    for (id, gpu) in gpus.iter() {
        let gpu_info = serde_json::json!({
            "id": id,
            "name": gpu.name,
            "vram_gb": gpu.vram_gb,
            "market_low_usd": format!("${:.2}", gpu.price_low_cents as f64 / 100.0),
            "market_mid_usd": format!("${:.2}", gpu.price_mid_cents as f64 / 100.0),
            "market_high_usd": format!("${:.2}", gpu.price_high_cents as f64 / 100.0),
            "bitsage_rate_usd": format!("${:.2}", gpu.bitsage_rate_cents as f64 / 100.0),
            "savings_vs_mid_pct": if gpu.price_mid_cents > 0 {
                format!("{:.0}%", (1.0 - gpu.bitsage_rate_cents as f64 / gpu.price_mid_cents as f64) * 100.0)
            } else {
                "N/A".to_string()
            },
        });

        match gpu.tier {
            GpuTier::Consumer => consumer.push(gpu_info),
            GpuTier::Professional => professional.push(gpu_info),
            GpuTier::Datacenter => datacenter.push(gpu_info),
            GpuTier::Enterprise => enterprise.push(gpu_info),
            GpuTier::Frontier => frontier.push(gpu_info),
        }
    }

    Json(serde_json::json!({
        "pricing_model": "market_competitive_usd",
        "last_updated": "2025-01-20",
        "sources": ["Lambda Labs", "Crusoe Cloud", "Hyperstack", "vast.ai", "CoreWeave", "Brev"],
        "tiers": {
            "frontier": {
                "description": "Next-gen AI accelerators (GB200, B200, MI300X)",
                "gpus": frontier,
            },
            "enterprise": {
                "description": "H100/H200 family for large-scale AI",
                "gpus": enterprise,
            },
            "datacenter": {
                "description": "A100, L40S, A40 for professional workloads",
                "gpus": datacenter,
            },
            "professional": {
                "description": "RTX 6000/A6000 workstation GPUs",
                "gpus": professional,
            },
            "consumer": {
                "description": "RTX 30xx/40xx/50xx gaming GPUs",
                "gpus": consumer,
            }
        },
        "total_gpu_models": gpus.len(),
    }))
}

async fn pricing_summary() -> Json<serde_json::Value> {
    Json(get_pricing_summary())
}

// =============================================================================
// Hybrid Supply Handlers
// =============================================================================

async fn supply_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = state.supply_router.get_supply_stats().await;

    Json(serde_json::json!({
        "supply_model": "hybrid_cloud_miner",
        "description": "BitSage combines cloud GPU providers with decentralized miners",

        "miner_network": {
            "total_miners": stats.total_miners,
            "online_miners": stats.online_miners,
            "total_gpus": stats.total_miner_gpus,
            "avg_load_pct": format!("{:.1}%", stats.avg_miner_load * 100.0),
            "cheapest_rate_usd": format!("${:.2}/hr", stats.cheapest_miner_rate as f64 / 100.0),
        },

        "cloud_supply": {
            "providers_enabled": stats.cloud_providers_enabled,
            "instance_types_available": stats.cloud_instance_types,
            "active_instances": stats.cloud_active_instances,
            "hourly_spend_usd": format!("${:.2}", stats.cloud_hourly_spend_cents as f64 / 100.0),
            "max_gpus_per_instance": stats.max_cloud_gpus,
            "cheapest_rate_usd": format!("${:.2}/hr", stats.cheapest_cloud_rate as f64 / 100.0),
        },

        "aggregated_providers": [
            "Hyperstack", "Lambda Labs", "Nebius", "IMWT",
            "Massed Compute", "Scaleway", "Voltage Park", "GCP"
        ],

        "bitsage_differentiators": {
            "zk_proofs": "STWO ZK proofs for verifiable computation",
            "tee_fhe": "TEE/FHE for confidential compute (Obelysk layer)",
            "sage_mining": "Earn SAGE tokens by contributing GPU power",
            "unified_api": "Single API across all providers + miners",
        },

        "fee_structure": {
            "cloud_markup": "20% on provider rates",
            "miner_split": "80% to miner, 20% protocol fee",
            "protocol_fee_breakdown": "70% burn, 20% treasury, 10% stakers",
        },
    }))
}

#[derive(Debug, Deserialize)]
struct RouteJobRequest {
    min_gpus: u32,
    min_vram_gib: u32,
    #[serde(default)]
    max_price_cents: Option<u32>,
    #[serde(default)]
    require_tee: bool,
    #[serde(default)]
    prefer_source: Option<String>, // "miner", "cloud", "hybrid"
}

async fn route_job(
    State(state): State<AppState>,
    Json(req): Json<RouteJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let preferred_source = match req.prefer_source.as_deref() {
        Some("miner") => SupplySource::Miner,
        Some("cloud") => SupplySource::Cloud,
        _ => SupplySource::Hybrid,
    };

    let preference = RoutingPreference {
        preferred_source,
        max_price_cents: req.max_price_cents,
        require_tee: req.require_tee,
        require_gpu_model: None,
        max_miner_wait_secs: 60,
        fallback_to_cloud: true,
    };

    match state.supply_router.route_job(req.min_gpus, req.min_vram_gib, preference).await {
        Ok(decision) => {
            Ok(Json(serde_json::json!({
                "status": "routed",
                "source": format!("{:?}", decision.source),
                "estimated_cost_usd": format!("${:.2}/hr", decision.estimated_cost_cents as f64 / 100.0),
                "worker_payment_usd": format!("${:.2}/hr", decision.worker_payment_cents as f64 / 100.0),
                "protocol_fee_usd": format!("${:.2}/hr", decision.protocol_fee_cents as f64 / 100.0),
                "estimated_wait_secs": decision.estimated_wait_secs,
                "tee_available": decision.tee_available,
                "reasoning": decision.reasoning,
                "miner": decision.miner.map(|m| serde_json::json!({
                    "miner_id": m.miner_id,
                    "gpu_model": m.gpu_model,
                    "gpu_count": m.gpu_count,
                    "reputation": m.reputation,
                })),
                "cloud_instance": decision.cloud_instance.map(|i| serde_json::json!({
                    "provider": i.provider.display_name(),
                    "instance_type": i.instance_type,
                    "gpu_model": i.gpu_model,
                    "gpu_count": i.gpu_count,
                    "interconnect": format!("{}", i.interconnect),
                })),
            })))
        }
        Err(e) => Err((StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
    }
}

async fn list_cloud_instances(State(_state): State<AppState>) -> Json<serde_json::Value> {
    // Get instances from provider manager (accessed through supply router's internal state)
    // For now, return the static pricing data
    let gpus = get_gpu_pricing();

    // Group by tier for better organization
    let mut instances_by_tier: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    for (id, gpu) in gpus.iter() {
        let tier_name = format!("{:?}", gpu.tier);
        instances_by_tier
            .entry(tier_name)
            .or_default()
            .push(serde_json::json!({
                "id": id,
                "name": gpu.name,
                "vram_gb": gpu.vram_gb,
                "bitsage_rate_usd": format!("${:.2}/hr", gpu.bitsage_rate_cents as f64 / 100.0),
            }));
    }

    Json(serde_json::json!({
        "source": "aggregated_cloud_providers",
        "providers": ["Hyperstack", "Lambda", "Nebius", "IMWT", "Voltage Park", "GCP"],
        "markup": "20% on provider rates",
        "instances_by_tier": instances_by_tier,
        "h100_highlights": {
            "cheapest_1x_h100": "$2.28/hr (Hyperstack PCIe)",
            "cheapest_8x_h100": "$18.72/hr (Hyperstack PCIe)",
            "with_tee": "$99.30/hr (GCP a3-highgpu-8g with Confidential Computing)",
        },
    }))
}

use std::collections::HashMap;

// =============================================================================
// Miner Registration Handlers
// =============================================================================

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RegisterMinerRequest {
    wallet_address: String,
    gpu_model: String,
    gpu_count: u32,
    vram_gib: u32,
    #[serde(default)]
    has_tee: bool,
    hourly_rate_cents: u32,
    #[serde(default)]
    tee_attestation: Option<String>, // Base64-encoded TEE attestation
}

async fn register_miner(
    State(state): State<AppState>,
    Json(req): Json<RegisterMinerRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Generate miner ID from wallet address
    let miner_id = format!("miner-{}", &req.wallet_address[0..10.min(req.wallet_address.len())]);

    // Get market rate for validation
    let market_rate = get_gpu_pricing()
        .values()
        .find(|g| g.name.contains(&req.gpu_model) || req.gpu_model.contains(g.name))
        .map(|g| g.bitsage_rate_cents)
        .unwrap_or(100);

    // Cap miner rate at 2x market rate
    let capped_rate = req.hourly_rate_cents.min(market_rate * 2);

    let miner = RegisteredMiner {
        miner_id: miner_id.clone(),
        wallet_address: req.wallet_address.clone(),
        gpu_model: req.gpu_model.clone(),
        gpu_count: req.gpu_count,
        vram_gib: req.vram_gib,
        has_tee: req.has_tee,
        current_load: 0.0,
        status: MinerStatus::Online,
        last_heartbeat: Utc::now(),
        jobs_completed: 0,
        reputation: 50, // Start at 50
        hourly_rate_cents: capped_rate,
        total_sage_earned: 0,
    };

    state.supply_router.register_miner(miner).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Broadcast to WebSocket
    state.ws_state.broadcast_worker_update(
        miner_id.clone(),
        "registered".to_string(),
        None,
        None,
    );

    Ok(Json(serde_json::json!({
        "status": "registered",
        "miner_id": miner_id,
        "wallet_address": req.wallet_address,
        "gpu_model": req.gpu_model,
        "gpu_count": req.gpu_count,
        "hourly_rate_usd": format!("${:.2}", capped_rate as f64 / 100.0),
        "market_rate_usd": format!("${:.2}", market_rate as f64 / 100.0),
        "rate_capped": req.hourly_rate_cents > market_rate * 2,
        "initial_reputation": 50,
        "sage_mining_enabled": true,
        "message": "Welcome to the BitSage mining network! Complete jobs to earn SAGE tokens.",
    })))
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct MinerHeartbeatRequest {
    miner_id: String,
    current_load: f64,
    #[serde(default)]
    status: Option<String>, // "online", "busy", "offline"
    #[serde(default)]
    gpu_temp_celsius: Option<f32>,
    #[serde(default)]
    gpu_utilization_pct: Option<f32>,
}

async fn miner_heartbeat(
    State(state): State<AppState>,
    Json(req): Json<MinerHeartbeatRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let status = match req.status.as_deref() {
        Some("busy") => MinerStatus::Busy,
        Some("offline") => MinerStatus::Offline,
        _ => MinerStatus::Online,
    };

    state.supply_router
        .update_miner_heartbeat(&req.miner_id, req.current_load, status)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    // Broadcast to WebSocket
    state.ws_state.broadcast_worker_update(
        req.miner_id.clone(),
        format!("{:?}", status).to_lowercase(),
        req.gpu_utilization_pct.map(|v| v as u32),
        Some((req.current_load * 100.0) as f32),
    );

    Ok(Json(serde_json::json!({
        "status": "ok",
        "miner_id": req.miner_id,
        "next_heartbeat_secs": 30,
    })))
}

async fn list_miners(State(state): State<AppState>) -> Json<serde_json::Value> {
    let miners = state.supply_router.list_online_miners().await;

    Json(serde_json::json!({
        "total_online": miners.len(),
        "miners": miners.iter().map(|m| serde_json::json!({
            "miner_id": m.miner_id,
            "gpu_model": m.gpu_model,
            "gpu_count": m.gpu_count,
            "vram_gib": m.vram_gib,
            "has_tee": m.has_tee,
            "load_pct": format!("{:.1}%", m.current_load * 100.0),
            "reputation": m.reputation,
            "hourly_rate_usd": format!("${:.2}", m.hourly_rate_cents as f64 / 100.0),
            "jobs_completed": m.jobs_completed,
            "total_sage_earned": m.total_sage_earned,
        })).collect::<Vec<_>>(),
    }))
}

async fn miner_status(
    State(state): State<AppState>,
    Path(miner_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let miners = state.supply_router.list_online_miners().await;

    if let Some(miner) = miners.iter().find(|m| m.miner_id == miner_id) {
        Ok(Json(serde_json::json!({
            "miner_id": miner.miner_id,
            "wallet_address": miner.wallet_address,
            "gpu_model": miner.gpu_model,
            "gpu_count": miner.gpu_count,
            "vram_gib": miner.vram_gib,
            "has_tee": miner.has_tee,
            "status": format!("{:?}", miner.status),
            "load_pct": format!("{:.1}%", miner.current_load * 100.0),
            "reputation": miner.reputation,
            "hourly_rate_usd": format!("${:.2}", miner.hourly_rate_cents as f64 / 100.0),
            "jobs_completed": miner.jobs_completed,
            "total_sage_earned": miner.total_sage_earned,
            "last_heartbeat": miner.last_heartbeat.to_rfc3339(),
        })))
    } else {
        Err((StatusCode::NOT_FOUND, format!("Miner {} not found", miner_id)))
    }
}

async fn miner_earnings(
    State(state): State<AppState>,
    Path(miner_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let miners = state.supply_router.list_online_miners().await;

    if let Some(miner) = miners.iter().find(|m| m.miner_id == miner_id) {
        // Calculate earnings breakdown
        let jobs = miner.jobs_completed;
        let total_sage = miner.total_sage_earned;
        let avg_sage_per_job = if jobs > 0 { total_sage / jobs } else { 0 };

        Ok(Json(serde_json::json!({
            "miner_id": miner.miner_id,
            "wallet_address": miner.wallet_address,

            "earnings_summary": {
                "total_sage_earned": total_sage,
                "jobs_completed": jobs,
                "avg_sage_per_job": avg_sage_per_job,
            },

            "current_rates": {
                "hourly_rate_usd": format!("${:.2}", miner.hourly_rate_cents as f64 / 100.0),
                "worker_share": "80%",
                "protocol_fee": "20%",
            },

            "mining_info": {
                "reputation": miner.reputation,
                "reputation_bonus": if miner.reputation >= 90 { "10%" } else if miner.reputation >= 70 { "5%" } else { "0%" },
                "next_halvening": "Block 1,000,000",
            },

            "withdrawal": {
                "can_withdraw": total_sage >= 1000,
                "min_withdrawal": 1000,
                "withdrawal_fee_pct": 0.1,
            },
        })))
    } else {
        Err((StatusCode::NOT_FOUND, format!("Miner {} not found", miner_id)))
    }
}

// =============================================================================
// Job Execution via Supply Router (Miner Mining Flow)
// =============================================================================

/// Submit a job through the supply router (routes to miners or cloud)
#[derive(Debug, Deserialize)]
struct ExecuteJobRequest {
    job_type: String,
    #[serde(default)]
    payload: Option<String>, // Payload as UTF-8 string (will be converted to bytes)
    #[serde(default)]
    min_gpus: Option<u32>,
    #[serde(default)]
    min_vram_gib: Option<u32>,
    #[serde(default)]
    require_tee: Option<bool>,
    #[serde(default)]
    max_price_cents: Option<u32>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    priority: Option<u32>,
    #[serde(default)]
    client_address: Option<String>,
    #[serde(default)]
    prefer_source: Option<String>, // "miner", "cloud", "hybrid"
    #[serde(default)]
    require_gpu_model: Option<String>,
}

async fn execute_job(
    State(state): State<AppState>,
    Json(req): Json<ExecuteJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Convert payload string to bytes
    let payload = req.payload
        .map(|p| p.into_bytes())
        .unwrap_or_default();

    let submit_request = SupplyJobSubmitRequest {
        job_type: req.job_type.clone(),
        payload,
        min_gpus: req.min_gpus,
        min_vram_gib: req.min_vram_gib,
        require_tee: req.require_tee,
        max_price_cents: req.max_price_cents,
        timeout_secs: req.timeout_secs,
        priority: req.priority,
        client_address: req.client_address.clone(),
        prefer_source: req.prefer_source.clone(),
        require_gpu_model: req.require_gpu_model.clone(),
    };

    match state.supply_router.submit_job(submit_request).await {
        Ok(response) => {
            // Broadcast job submission to WebSocket subscribers
            state.ws_state.broadcast_job_update(
                response.job_id.clone(),
                format!("{:?}", response.status),
                None,
                response.assigned_miner.clone(),
            );

            Ok(Json(serde_json::json!({
                "status": "submitted",
                "job_id": response.job_id,
                "execution_status": format!("{:?}", response.status),
                "assigned_miner": response.assigned_miner,
                "estimated_cost_usd": format!("${:.2}/hr", response.estimated_cost_cents as f64 / 100.0),
                "estimated_wait_secs": response.estimated_wait_secs,
                "route": {
                    "source": format!("{:?}", response.route_decision.source),
                    "worker_payment_usd": format!("${:.2}", response.route_decision.worker_payment_cents as f64 / 100.0),
                    "protocol_fee_usd": format!("${:.2}", response.route_decision.protocol_fee_cents as f64 / 100.0),
                    "tee_available": response.route_decision.tee_available,
                    "reasoning": response.route_decision.reasoning,
                },
                "poll_endpoint": response.assigned_miner.as_ref().map(|m| format!("/api/miners/{}/poll-job", m)),
                "status_endpoint": format!("/api/jobs/{}/miner-status", response.job_id),
            })))
        }
        Err(e) => Err((StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
    }
}

/// Miner polls for jobs assigned to them
async fn poll_miner_job(
    State(state): State<AppState>,
    Path(miner_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.supply_router.poll_job_for_miner(&miner_id).await {
        Some(assignment) => {
            // Broadcast job started to WebSocket
            state.ws_state.broadcast_job_update(
                assignment.job_id.clone(),
                "Running".to_string(),
                None,
                Some(miner_id.clone()),
            );

            // Convert payload bytes to string (lossy conversion for display)
            let payload_str = String::from_utf8_lossy(&assignment.payload).to_string();

            Ok(Json(serde_json::json!({
                "status": "job_assigned",
                "job": {
                    "job_id": assignment.job_id,
                    "job_type": assignment.job_type,
                    "payload": payload_str,
                    "payload_size_bytes": assignment.payload.len(),
                    "timeout_secs": assignment.timeout_secs,
                    "require_tee": assignment.require_tee,
                    "estimated_payment_usd": format!("${:.2}", assignment.estimated_payment_cents as f64 / 100.0),
                },
                "instructions": {
                    "complete_endpoint": format!("/api/jobs/{}/complete-mined", assignment.job_id),
                    "fail_endpoint": format!("/api/jobs/{}/fail-mined", assignment.job_id),
                    "timeout_behavior": "Job auto-fails if not completed within timeout",
                },
            })))
        }
        None => {
            Ok(Json(serde_json::json!({
                "status": "no_jobs",
                "miner_id": miner_id,
                "message": "No jobs currently assigned. Keep polling or wait for WebSocket notification.",
                "poll_interval_secs": 5,
            })))
        }
    }
}

/// Miner completes a job with result
#[derive(Debug, Deserialize)]
struct CompleteMinerJobRequest {
    miner_id: String,
    #[serde(default)]
    output: Option<String>, // Output as UTF-8 string
    #[serde(default)]
    proof: Option<String>, // ZK proof as hex string
    #[serde(default)]
    proof_hash: Option<String>,
    gpu_seconds: u64,
    #[serde(default)]
    metrics: Option<serde_json::Value>,
}

async fn complete_mined_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(req): Json<CompleteMinerJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Convert output string to bytes
    let output = req.output
        .map(|o| o.into_bytes())
        .unwrap_or_default();

    // Convert proof hex string to bytes (if provided)
    let proof = req.proof
        .map(|p| hex::decode(p.trim_start_matches("0x")).unwrap_or_else(|_| p.into_bytes()));

    let result = SupplyJobResult {
        output,
        proof,
        proof_hash: req.proof_hash,
        gpu_seconds: req.gpu_seconds,
        metrics: req.metrics,
    };

    match state.supply_router.complete_job(&req.miner_id, &job_id, result).await {
        Ok(payout) => {
            // Broadcast job completion to WebSocket
            state.ws_state.broadcast_job_update(
                job_id.clone(),
                "Completed".to_string(),
                Some(format!("{} SAGE earned", payout.total_sage_payout)),
                Some(req.miner_id.clone()),
            );

            Ok(Json(serde_json::json!({
                "status": "completed",
                "job_id": job_id,
                "payout": {
                    "miner_id": payout.miner_id,
                    "miner_wallet": payout.miner_wallet,
                    "total_cost_usd": format!("${:.4}", payout.total_cost_cents as f64 / 100.0),
                    "worker_payment_usd": format!("${:.4}", payout.worker_payment_cents as f64 / 100.0),
                    "protocol_fee_usd": format!("${:.4}", payout.protocol_fee_cents as f64 / 100.0),
                    "sage_amount": payout.sage_amount,
                    "sage_price_usd": payout.sage_price_usd,
                    "mining_bonus_sage": payout.mining_bonus_sage,
                    "total_sage_payout": payout.total_sage_payout,
                    "paid_at": payout.paid_at.to_rfc3339(),
                },
                "message": format!("Congratulations! You earned {} SAGE (+ {} bonus)", payout.sage_amount, payout.mining_bonus_sage),
            })))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string()))
    }
}

/// Miner reports job failure
#[derive(Debug, Deserialize)]
struct FailMinerJobRequest {
    miner_id: String,
    error: String,
}

async fn fail_mined_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(req): Json<FailMinerJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.supply_router.fail_job(&req.miner_id, &job_id, req.error.clone()).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Broadcast job failure to WebSocket
    state.ws_state.broadcast_job_update(
        job_id.clone(),
        "Failed".to_string(),
        Some(req.error.clone()),
        Some(req.miner_id.clone()),
    );

    Ok(Json(serde_json::json!({
        "status": "failed",
        "job_id": job_id,
        "miner_id": req.miner_id,
        "error": req.error,
        "reputation_penalty": 2,
        "message": "Job marked as failed. Reputation reduced by 2 points.",
    })))
}

/// Get job status from supply router
async fn miner_job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.supply_router.get_job(&job_id).await {
        Some(job) => {
            Ok(Json(serde_json::json!({
                "job_id": job.job_id,
                "job_type": job.job_type,
                "status": format!("{:?}", job.status),
                "assigned_miner": job.assigned_miner,
                "require_tee": job.require_tee,
                "min_gpus": job.min_gpus,
                "min_vram_gib": job.min_vram_gib,
                "priority": job.priority,
                "timeout_secs": job.timeout_secs,
                "timestamps": {
                    "created_at": job.created_at.to_rfc3339(),
                    "started_at": job.started_at.map(|t| t.to_rfc3339()),
                    "completed_at": job.completed_at.map(|t| t.to_rfc3339()),
                },
                "execution_time_ms": job.execution_time_ms,
                "error": job.error,
                "route": job.route_decision.as_ref().map(|r| serde_json::json!({
                    "source": format!("{:?}", r.source),
                    "estimated_cost_cents": r.estimated_cost_cents,
                    "reasoning": r.reasoning,
                })),
            })))
        }
        None => Err((StatusCode::NOT_FOUND, format!("Job {} not found", job_id)))
    }
}

/// Get job execution statistics
async fn miner_job_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = state.supply_router.get_job_stats().await;

    Json(serde_json::json!({
        "job_execution_stats": {
            "total_jobs": stats.total_jobs,
            "pending_jobs": stats.pending_jobs,
            "queued_jobs": stats.queued_jobs,
            "running_jobs": stats.running_jobs,
            "completed_jobs": stats.completed_jobs,
            "failed_jobs": stats.failed_jobs,
            "success_rate_pct": if stats.total_jobs > 0 {
                format!("{:.1}%", (stats.completed_jobs as f64 / stats.total_jobs as f64) * 100.0)
            } else {
                "N/A".to_string()
            },
        },
        "economics": {
            "total_sage_paid": stats.total_sage_paid,
            "total_revenue_usd": format!("${:.2}", stats.total_revenue_cents as f64 / 100.0),
            "avg_execution_time_ms": stats.avg_execution_time_ms,
        },
        "fee_structure": {
            "worker_share": "80%",
            "protocol_fee": "20%",
            "protocol_breakdown": "70% burn, 20% treasury, 10% stakers",
        },
    }))
}

// =============================================================================
// Shutdown Handler
// =============================================================================

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
