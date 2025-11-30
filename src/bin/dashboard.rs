//! # Bitsage Network Indexer Dashboard
//!
//! Simple web dashboard to view indexed blockchain events.

use anyhow::Result;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, Json},
    routing::get,
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::fs;
use std::path::Path;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{info, error};
use tracing_subscriber;

use bitsage_node::SimpleDatabase as DatabaseManager;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Database URL
    #[arg(long)]
    database_url: String,
    
    /// Port to run dashboard on
    #[arg(long, default_value = "3000")]
    port: u16,
}

#[derive(Debug, Serialize)]
struct DashboardStats {
    total_events: u64,
    total_blocks: u64,
    last_block: u64,
    events_by_type: HashMap<String, u64>,
    events_by_contract: HashMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct EventSummary {
    event_type: String,
    contract_address: String,
    block_number: u64,
    timestamp: u64,
    data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    limit: Option<u32>,
    offset: Option<u32>,
    contract: Option<String>,
    event_type: Option<String>,
}

struct AppState {
    database: Arc<DatabaseManager>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,bitsage_node=debug")
        .init();

    let args = Args::parse();

    info!("Starting Bitsage Network Indexer Dashboard");
    
    // Initialize database
    let database = Arc::new(DatabaseManager::new(&args.database_url).await?);
    
    // Test database connection
    match database.health_check().await {
        Ok(_) => info!("✅ Connected to database successfully"),
        Err(e) => {
            error!("❌ Failed to connect to database: {}", e);
            return Err(e);
        }
    }

    let state = Arc::new(AppState { database });

    // Build router
    let app = Router::new()
        .route("/", get(dashboard_html))
        .route("/api/stats", get(get_stats))
        .route("/api/events", get(get_events))
        .route("/api/contracts", get(get_contracts))
        .with_state(state)
        .layer(ServiceBuilder::new().layer(CorsLayer::permissive()));

    let listener = TcpListener::bind(&format!("0.0.0.0:{}", args.port)).await?;
    
    info!("🚀 Dashboard running on http://localhost:{}", args.port);
    info!("📊 View your indexed events at http://localhost:{}", args.port);
    
    axum::serve(listener, app).await?;

    Ok(())
}

async fn dashboard_html() -> Html<&'static str> {
    Html(include_str!("../../templates/dashboard.html"))
}

async fn get_stats(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<DashboardStats>, StatusCode> {
    // Get real event statistics from database
    let (total_events, events_by_type, events_by_contract) = state.database
        .get_event_stats()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get event stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Get block metrics (latest block and distinct blocks with events)
    let (last_block, total_blocks) = state.database
        .get_block_stats()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get block stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let stats = DashboardStats {
        total_events: total_events as u64,
        total_blocks: total_blocks as u64,
        last_block: last_block as u64,
        events_by_type: events_by_type.into_iter().map(|(k, v)| (k, v as u64)).collect(),
        events_by_contract: events_by_contract.into_iter().map(|(k, v)| (k, v as u64)).collect(),
    };
    
    Ok(Json(stats))
}

async fn get_events(
    Query(params): Query<EventQuery>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<Vec<EventSummary>>, StatusCode> {
    let limit = params.limit.unwrap_or(50) as i64;
    let offset = params.offset.unwrap_or(0) as i64;
    let contract = params.contract.as_deref();
    let event_type = params.event_type.as_deref();

    // Get filtered or recent events from database
    let events = state.database
        .get_events_filtered(contract, event_type, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get events: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Convert to EventSummary format
    let event_summaries: Vec<EventSummary> = events
        .into_iter()
        .map(|event| EventSummary {
            contract_address: event.contract_address,
            event_type: event.event_type,
            block_number: event.block_number,
            timestamp: event.timestamp,
            data: event.data,
        })
        .collect();
    
    Ok(Json(event_summaries))
}

async fn get_contracts(
    axum::extract::State(_state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    // Attempt to load ReputationManager current address from deployment JSON
    #[derive(Deserialize)]
    struct ReputationManagerEntry { contract_address: String }
    #[derive(Deserialize)]
    struct ContractsFile { reputation_manager: ReputationManagerEntry }

    let mut rm_addr = "0x02f0ce7e13e113e91f3a4669f742e7470f2bdfb3c7146aff1d449fddf92b7dc0".to_string();
    let default_path = "../cairo-contracts/reputation_manager_deployment.json".to_string();
    if Path::new(&default_path).exists() {
        if let Ok(contents) = fs::read_to_string(&default_path) {
            if let Ok(parsed) = serde_json::from_str::<ContractsFile>(&contents) {
                if !parsed.reputation_manager.contract_address.is_empty() {
                    rm_addr = parsed.reputation_manager.contract_address;
                }
            }
        }
    }

    // Attempt to load SAGE Token current address from a root contracts.json file
    #[derive(Deserialize)]
    struct RootContracts { sage_token: String }

    // Default token address (legacy); will be overridden if contracts.json is found
    let mut sage_token_addr = "0x03c0f7574905d7cbc2cca18d6c090265fa35b572d8e9dc62efeb5339908720d8".to_string();

    // Try common relative locations so running from different working directories still works
    let candidates = [
        "./contracts.json",
        "../contracts.json",
        "../../contracts.json",
    ];
    for candidate in candidates.iter() {
        if Path::new(candidate).exists() {
            if let Ok(contents) = fs::read_to_string(candidate) {
                if let Ok(parsed) = serde_json::from_str::<RootContracts>(&contents) {
                    if !parsed.sage_token.is_empty() {
                        sage_token_addr = parsed.sage_token;
                        break;
                    }
                }
            }
        }
    }

    // Return Bitsage Network contracts with current addresses
    let contracts = vec![
        serde_json::json!({
            "name": "SAGE Token",
            "address": sage_token_addr,
            "contract_type": "sage_token",
            "is_active": true
        }),
        serde_json::json!({
            "name": "Linear Vesting",
            "address": "0x06d2e5684aa4e3fbf3cec0a2594f5dfb7f085e08b8c3debf65ac2e546f49f96c",
            "contract_type": "linear_vesting",
            "is_active": true
        }),
        serde_json::json!({
            "name": "Milestone Vesting",
            "address": "0x0475fa46216ed145be825177db2e565ea4abb6d974466ebeaedaf7e3b6d07675",
            "contract_type": "milestone_vesting",
            "is_active": true
        }),
        serde_json::json!({
            "name": "Burn Manager",
            "address": "0x0362a11c3ec6bd17e169d53c5affe5358b0825233cbbeb0043f5d00ffdc6eb3a",
            "contract_type": "burn_manager",
            "is_active": true
        }),
        serde_json::json!({
            "name": "CDC Pool",
            "address": "0x05f73c551dbfda890090c8ee89858992dfeea9794a63ad83e6b1706e9836aeba",
            "contract_type": "cdc_pool",
            "is_active": true
        }),
        serde_json::json!({
            "name": "Job Manager",
            "address": "0x00bf025663b8a7c7e43393f082b10afe66bd9ddb06fb5e521e3adbcf693094bd",
            "contract_type": "job_manager",
            "is_active": true
        }),
        serde_json::json!({
            "name": "Treasury Timelock",
            "address": "0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7",
            "contract_type": "treasury_timelock",
            "is_active": true
        }),
        serde_json::json!({
            "name": "Reputation Manager",
            "address": rm_addr,
            "contract_type": "reputation_manager",
            "is_active": true
        }),
        serde_json::json!({
            "name": "SimpleEvents",
            "address": "0x00a46bca3ae494eedbd606346264bb36c8dbd51a103c195a197602253228a72e",
            "contract_type": "simple_events",
            "is_active": true
        })
    ];
    
    Ok(Json(contracts))
}