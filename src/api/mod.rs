//! # REST API Module
//!
//! Provides HTTP/REST API endpoints for the BitSage Network

pub mod job_monitoring;
pub mod job_submission;
pub mod faucet;
pub mod websocket;
pub mod dashboard;
pub mod captcha;
pub mod staking;
pub mod trading;
pub mod governance;
pub mod privacy;
pub mod privacy_swap;
pub mod metrics;
pub mod health;
pub mod metrics_aggregator;
pub mod proof_generation;
pub mod worker_heartbeat;
pub mod cache;

// Database-backed API modules (DEV 1)
pub mod jobs_db;
pub mod proofs_db;
pub mod staking_db;
pub mod earnings_db;
pub mod wallet_db;
pub mod network_db;
pub mod dashboard_db;

// Gasless transaction relayer
pub mod relayer;

pub use job_monitoring::{create_monitoring_router, MonitoringApiState};
pub use job_submission::{create_submission_router, SubmissionApiState};
pub use faucet::{faucet_routes, FaucetApiState};
pub use websocket::{websocket_routes, WebSocketState, WsEvent, JobUpdateEvent, WorkerUpdateEvent, NetworkStatsEvent, ProofVerifiedEvent};
pub use dashboard::{dashboard_routes, DashboardApiState, DashboardContracts};
pub use captcha::{CaptchaVerifier, CaptchaConfig, CaptchaProvider, config_from_env as captcha_config_from_env};
pub use staking::{staking_routes, StakingApiState};
pub use trading::{trading_routes, TradingApiState};
pub use governance::{governance_routes, GovernanceApiState};
pub use privacy::{privacy_routes, PrivacyApiState};
pub use privacy_swap::{privacy_swap_routes, PrivacySwapState};
pub use metrics::metrics_routes;
pub use health::health_routes;
pub use proof_generation::{proof_generation_routes, ProofGenerationState};
pub use worker_heartbeat::{worker_heartbeat_routes, WorkerHeartbeatState};
pub use cache::{DashboardCache, CacheConfig, CacheKeys, CacheTTL, CacheStats, cache_cleanup_task};

// Database-backed API exports
pub use jobs_db::{jobs_db_routes, JobsDbState};
pub use proofs_db::{proofs_db_routes, ProofsDbState};
pub use staking_db::{staking_db_routes, StakingDbState};
pub use earnings_db::{earnings_db_routes, EarningsDbState};
pub use wallet_db::{wallet_db_routes, WalletDbState};
pub use network_db::{network_db_routes, NetworkDbState};
pub use dashboard_db::{dashboard_db_routes, DashboardDbState};

// Relayer API exports
pub use relayer::{relayer_routes, RelayerState, RelayerConfig};

