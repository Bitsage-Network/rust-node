//! # Bitsage Network Event Indexer
//!
//! Standalone service for indexing blockchain events from Bitsage Network smart contracts.

use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use std::fs;
use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error};
use tracing_subscriber;

use bitsage_node::{StarknetClient, SimpleDatabase as DatabaseManager};
use bitsage_node::blockchain::events::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Starknet RPC URL
    #[arg(long, default_value = "https://starknet-sepolia.public.blastapi.io")]
    rpc_url: String,
    
    /// Database URL
    #[arg(long)]
    database_url: String,
    
    /// Poll interval in seconds
    #[arg(long, default_value = "5")]
    poll_interval: u64,
    
    /// Batch size for processing blocks
    #[arg(long, default_value = "100")]
    batch_size: u64,
    
    /// Whether to index historical blocks
    #[arg(long)]
    index_historical: bool,
    
    /// Starting block for historical indexing
    #[arg(long, default_value = "0")]
    start_block: u64,
    
    /// Treasury Timelock contract address
    #[arg(long, default_value = "0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7")]
    treasury_timelock: String,
    
    /// Reputation Manager contract address
    #[arg(long, default_value = "0x02f0ce7e13e113e91f3a4669f742e7470f2bdfb3c7146aff1d449fddf92b7dc0")]
    reputation_manager: String,
    
    /// Job Manager contract address (placeholder)
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    job_manager: String,
    
    /// CDC Pool contract address (placeholder)
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    cdc_pool: String,
    
    /// SAGE Token contract address (placeholder)
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    sage_token: String,
    
    /// Governance Treasury contract address (placeholder)
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    governance_treasury: String,
    
    /// SimpleEvents test contract address
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    simple_events: String,

    /// Linear Vesting contract address
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    linear_vesting: String,

    /// Milestone Vesting contract address
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    milestone_vesting: String,

    /// Burn Manager contract address
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000000000000000000000000000")]
    burn_manager: String,

    /// Optional path to contracts deployment JSON (will override individual addresses if present)
    #[arg(long)]
    contracts_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,bitsage_node=debug,bitsage_node=debug")
        .init();

    let args = Args::parse();

    info!("Starting Bitsage Network Event Indexer");
    info!("RPC URL: {}", args.rpc_url);
    info!("Poll interval: {} seconds", args.poll_interval);
    
    // Initialize blockchain client
    let client = Arc::new(StarknetClient::new(args.rpc_url)?);
    
    // Test connection
    match client.connect().await {
        Ok(_) => info!("✅ Connected to Starknet successfully"),
        Err(e) => {
            error!("❌ Failed to connect to Starknet: {}", e);
            return Err(e);
        }
    }
    
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

    // Ensure schema exists
    if let Err(e) = database.initialize().await {
        error!("❌ Failed to initialize database schema: {}", e);
        return Err(e);
    }

    // Optionally load addresses from contracts file
    #[derive(Deserialize)]
    struct ReputationManagerEntry { contract_address: String }
    #[derive(Deserialize)]
    struct ContractsFile { reputation_manager: ReputationManagerEntry }

    let mut reputation_manager_addr = args.reputation_manager.clone();
    if let Some(path) = args.contracts_file.clone().or_else(|| {
        let default_path = "../cairo-contracts/reputation_manager_deployment.json".to_string();
        if Path::new(&default_path).exists() { Some(default_path) } else { None }
    }) {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                if let Ok(parsed) = serde_json::from_str::<ContractsFile>(&contents) {
                    if !parsed.reputation_manager.contract_address.is_empty() {
                        reputation_manager_addr = parsed.reputation_manager.contract_address;
                        info!("Loaded Reputation Manager address from {}", path);
                    }
                } else {
                    info!("Contracts file found but could not be parsed; using CLI defaults: {}", path);
                }
            }
            Err(_) => {
                info!("Contracts file not readable; using CLI defaults: {}", path);
            }
        }
    }

    // Parse contract addresses
    let contracts = ContractAddresses {
        job_manager: parse_address(&args.job_manager)?,
        cdc_pool: parse_address(&args.cdc_pool)?,
        treasury_timelock: parse_address(&args.treasury_timelock)?,
        sage_token: parse_address(&args.sage_token)?,
        governance_treasury: parse_address(&args.governance_treasury)?,
        reputation_manager: parse_address(&reputation_manager_addr)?,
        simple_events: parse_address(&args.simple_events)?,
        linear_vesting: parse_address(&args.linear_vesting)?,
        milestone_vesting: parse_address(&args.milestone_vesting)?,
        burn_manager: parse_address(&args.burn_manager)?,
    };

    info!("Monitoring contracts:");
    info!("  Treasury Timelock: 0x{:x}", contracts.treasury_timelock);
    info!("  Reputation Manager: 0x{:x}", contracts.reputation_manager);
    if contracts.job_manager != parse_address("0x0000000000000000000000000000000000000000000000000000000000000000")? {
        info!("  Job Manager: 0x{:x}", contracts.job_manager);
    }
    if contracts.cdc_pool != parse_address("0x0000000000000000000000000000000000000000000000000000000000000000")? {
        info!("  CDC Pool: 0x{:x}", contracts.cdc_pool);
    }

    // Configure indexer
    let config = IndexerConfig {
        poll_interval_secs: args.poll_interval,
        batch_size: args.batch_size,
        max_retries: 3,
        retry_delay_ms: 1000,
        index_historical: args.index_historical,
        start_block: args.start_block,
    };

    // Create and start indexer
    let indexer = EventIndexer::new(client, database, config, contracts);
    
    // Start indexer in background
    let indexer_handle = {
        let indexer = indexer.clone();
        tokio::spawn(async move {
            if let Err(e) = indexer.start().await {
                error!("Indexer failed: {}", e);
            }
        })
    };

    // Start statistics reporting
    let stats_handle = {
        let indexer = indexer.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let stats = indexer.get_stats().await;
                info!(
                    "📊 Indexer Stats - Blocks: {}, Events: {}, Last Block: {}",
                    stats.blocks_processed, stats.events_indexed, stats.last_block
                );
            }
        })
    };

    info!("🚀 Bitsage Network Event Indexer is running!");
    info!("Press Ctrl+C to stop");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    
    info!("Shutdown signal received, stopping indexer...");
    
    // Stop indexer
    indexer.stop().await;
    
    // Cancel background tasks
    indexer_handle.abort();
    stats_handle.abort();
    
    info!("✅ Indexer stopped successfully");
    
    Ok(())
}

fn parse_address(addr: &str) -> Result<starknet::core::types::FieldElement> {
    use starknet::core::types::FieldElement;
    Ok(FieldElement::from_hex_be(addr)?)
}

