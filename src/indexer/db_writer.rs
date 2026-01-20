//! # Database Writer
//!
//! Writes processed events to PostgreSQL database.
//! Handles batch inserts and updates to maintain data consistency.
//! Integrates with WebSocket for real-time event broadcasting.

use sqlx::{PgPool, postgres::PgPoolOptions, Row};
use std::sync::Arc;
use tracing::{debug, info, warn};
use chrono::{DateTime, Utc};

use super::event_processor::ProcessedEvent;
use super::IndexerError;
use crate::api::websocket::WebSocketState;

/// Database writer for the indexer with optional WebSocket broadcasting
pub struct DbWriter {
    pool: PgPool,
    /// Optional WebSocket state for real-time event broadcasting
    ws_state: Option<Arc<WebSocketState>>,
}

impl DbWriter {
    /// Create a new DbWriter with a connection pool
    pub async fn new(database_url: &str) -> Result<Self, IndexerError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;

        info!("Connected to PostgreSQL database");

        Ok(Self { pool, ws_state: None })
    }

    /// Create a new DbWriter with WebSocket integration
    pub async fn new_with_websocket(database_url: &str, ws_state: Arc<WebSocketState>) -> Result<Self, IndexerError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;

        info!("Connected to PostgreSQL database with WebSocket broadcasting enabled");

        Ok(Self { pool, ws_state: Some(ws_state) })
    }

    /// Set the WebSocket state for broadcasting
    pub fn set_websocket_state(&mut self, ws_state: Arc<WebSocketState>) {
        self.ws_state = Some(ws_state);
        info!("WebSocket broadcasting enabled for indexer");
    }
    
    /// Write a processed event to the appropriate tables and broadcast via WebSocket
    pub async fn write_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        // Always write to blockchain_events table for raw event log
        self.write_raw_event(event).await?;

        // Write to specific tables based on contract and event type
        match event.contract_name.as_str() {
            "JobManager" => self.handle_job_event(event).await?,
            "Staking" => self.handle_staking_event(event).await?,
            "OTCOrderbook" => self.handle_otc_event(event).await?,
            "Governance" => self.handle_governance_event(event).await?,
            "PrivacyRouter" => self.handle_privacy_event(event).await?,
            "ProofVerifier" => self.handle_proof_event(event).await?,
            "Reputation" => self.handle_reputation_event(event).await?,
            "Referral" => self.handle_referral_event(event).await?,
            "Faucet" => self.handle_faucet_event(event).await?,
            _ => {
                warn!("Unknown contract: {}", event.contract_name);
            }
        }

        // Broadcast event via WebSocket if enabled
        self.broadcast_event(event);

        Ok(())
    }

    /// Broadcast an indexed event via WebSocket to connected clients
    fn broadcast_event(&self, event: &ProcessedEvent) {
        let Some(ws_state) = &self.ws_state else {
            return;
        };

        let _timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match event.contract_name.as_str() {
            "JobManager" => {
                self.broadcast_job_event(ws_state, event);
            }
            "Staking" => {
                let worker = event.event_data["worker"].as_str().unwrap_or("0").to_string();
                let amount = event.event_data["amount"].as_str().unwrap_or("0").to_string();
                let gpu_tier = event.event_data["gpu_tier"].as_str().map(|s| s.to_string());

                ws_state.broadcast_staking(
                    worker,
                    event.event_name.clone(),
                    amount,
                    gpu_tier,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            "OTCOrderbook" => {
                self.broadcast_otc_event(ws_state, event);
            }
            "Governance" => {
                self.broadcast_governance_event(ws_state, event);
            }
            "PrivacyRouter" => {
                let nullifier = event.event_data["nullifier"].as_str().map(|s| s.to_string());
                ws_state.broadcast_privacy(
                    event.event_name.clone(),
                    nullifier,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            "ProofVerifier" => {
                if event.event_name == "ProofVerified" {
                    let job_id = event.event_data["job_id"].as_str().unwrap_or("0").to_string();
                    let proof_hash = event.event_data["proof_hash"].as_str().unwrap_or("0").to_string();
                    let verifier = event.event_data["verifier"].as_str().unwrap_or("0").to_string();
                    let is_valid = event.event_data["is_valid"].as_bool().unwrap_or(false);
                    let gas_used = event.event_data["gas_used"].as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0);

                    ws_state.broadcast_proof_verified(
                        job_id,
                        proof_hash,
                        verifier,
                        is_valid,
                        gas_used,
                    );
                }
            }
            "Faucet" => {
                if event.event_name == "Claimed" {
                    let claimer = event.event_data["claimer"].as_str().unwrap_or("0").to_string();
                    let amount = event.event_data["amount"].as_str().unwrap_or("0").to_string();

                    ws_state.broadcast_faucet_claim(
                        claimer,
                        amount,
                        event.transaction_hash.clone(),
                        event.block_number,
                    );
                }
            }
            _ => {
                // Broadcast generic indexed event for unknown contracts
                ws_state.broadcast_indexed(
                    event.contract_name.clone(),
                    event.event_name.clone(),
                    event.event_data.clone(),
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
        }

        debug!(
            "Broadcast {} event from {} via WebSocket",
            event.event_name, event.contract_name
        );
    }

    /// Broadcast job manager events
    fn broadcast_job_event(&self, ws_state: &Arc<WebSocketState>, event: &ProcessedEvent) {
        let job_id = event.event_data["job_id"].as_str().unwrap_or("0").to_string();

        match event.event_name.as_str() {
            "JobSubmitted" => {
                ws_state.broadcast_job_update(
                    job_id,
                    "pending".to_string(),
                    None,
                    None,
                );
            }
            "JobAssigned" => {
                let worker = event.event_data["worker"].as_str().map(|s| s.to_string());
                ws_state.broadcast_job_update(
                    job_id,
                    "assigned".to_string(),
                    worker,
                    None,
                );
            }
            "JobCompleted" => {
                let worker = event.event_data["worker"].as_str().map(|s| s.to_string());
                let result_hash = event.event_data["result_hash"].as_str().map(|s| s.to_string());
                ws_state.broadcast_job_update(
                    job_id,
                    "completed".to_string(),
                    worker,
                    result_hash,
                );
            }
            "JobCancelled" => {
                ws_state.broadcast_job_update(
                    job_id,
                    "cancelled".to_string(),
                    None,
                    None,
                );
            }
            _ => {}
        }
    }

    /// Broadcast OTC orderbook events
    fn broadcast_otc_event(&self, ws_state: &Arc<WebSocketState>, event: &ProcessedEvent) {
        match event.event_name.as_str() {
            "OrderPlaced" => {
                let order_id = event.event_data["order_id"].as_str().unwrap_or("0").to_string();
                let maker = event.event_data["maker"].as_str().unwrap_or("0").to_string();
                let pair_id = event.event_data["pair_id"].as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let side = if event.event_data["side"].as_str().unwrap_or("0") == "1" {
                    "sell".to_string()
                } else {
                    "buy".to_string()
                };
                let price = event.event_data["price"].as_str().unwrap_or("0").to_string();
                let amount = event.event_data["amount"].as_str().unwrap_or("0").to_string();

                ws_state.broadcast_order_placed(
                    order_id,
                    maker,
                    pair_id,
                    side,
                    price,
                    amount,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            "OrderFilled" => {
                let order_id = event.event_data["order_id"].as_str().unwrap_or("0").to_string();
                let filled = event.event_data["filled_amount"].as_str().map(|s| s.to_string());
                let remaining = event.event_data["remaining_amount"].as_str().map(|s| s.to_string());
                let status = if remaining.as_deref() == Some("0") {
                    "filled".to_string()
                } else {
                    "partial".to_string()
                };

                ws_state.broadcast_order_update(
                    order_id,
                    status,
                    filled,
                    remaining,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            "OrderCancelled" => {
                let order_id = event.event_data["order_id"].as_str().unwrap_or("0").to_string();

                ws_state.broadcast_order_update(
                    order_id,
                    "cancelled".to_string(),
                    None,
                    None,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            "TradeExecuted" => {
                let trade_id = event.event_data["trade_id"].as_str().unwrap_or("0").to_string();
                let pair_id = event.event_data["pair_id"].as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let maker = event.event_data["maker"].as_str().unwrap_or("0").to_string();
                let taker = event.event_data["taker"].as_str().unwrap_or("0").to_string();
                let price = event.event_data["price"].as_str().unwrap_or("0").to_string();
                let amount = event.event_data["amount"].as_str().unwrap_or("0").to_string();
                let side = event.event_data["side"].as_str().unwrap_or("buy").to_string();

                ws_state.broadcast_trade(
                    trade_id,
                    pair_id,
                    maker,
                    taker,
                    price,
                    amount,
                    side,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            _ => {}
        }
    }

    /// Broadcast governance events
    fn broadcast_governance_event(&self, ws_state: &Arc<WebSocketState>, event: &ProcessedEvent) {
        match event.event_name.as_str() {
            "ProposalCreated" => {
                let proposal_id = event.event_data["proposal_id"].as_str().unwrap_or("0").to_string();
                let proposer = event.event_data["proposer"].as_str().unwrap_or("0").to_string();
                let proposal_type = event.event_data["proposal_type"].as_str().unwrap_or("general").to_string();
                let title = event.event_data["title"].as_str().map(|s| s.to_string());

                ws_state.broadcast_proposal(
                    proposal_id,
                    proposer,
                    proposal_type,
                    title,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            "VoteCast" => {
                let proposal_id = event.event_data["proposal_id"].as_str().unwrap_or("0").to_string();
                let voter = event.event_data["voter"].as_str().unwrap_or("0").to_string();
                let support = event.event_data["support"].as_str()
                    .and_then(|s| s.parse::<u8>().ok())
                    .unwrap_or(0);
                let voting_power = event.event_data["voting_power"].as_str().unwrap_or("0").to_string();

                ws_state.broadcast_vote(
                    proposal_id,
                    voter,
                    support,
                    voting_power,
                    event.transaction_hash.clone(),
                    event.block_number,
                );
            }
            _ => {}
        }
    }
    
    /// Write raw event to blockchain_events table
    async fn write_raw_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        sqlx::query(
            r#"
            INSERT INTO blockchain_events 
                (contract_address, contract_name, event_name, event_data, tx_hash, block_number, block_timestamp, processed)
            VALUES ($1, $2, $3, $4, $5, $6, $7, true)
            ON CONFLICT (tx_hash, contract_address, event_name) DO NOTHING
            "#
        )
        .bind(&event.contract_address)
        .bind(&event.contract_name)
        .bind(&event.event_name)
        .bind(&event.event_data)
        .bind(&event.transaction_hash)
        .bind(event.block_number as i64)
        .bind(event.block_timestamp.map(|ts| DateTime::from_timestamp(ts as i64, 0).unwrap_or(Utc::now())))
        .execute(&self.pool)
        .await
        .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Handle JobManager events
    async fn handle_job_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "JobSubmitted" => {
                let job_id = event.event_data["job_id"].as_str().unwrap_or("0");
                let client = event.event_data["client"].as_str().unwrap_or("0");
                let job_type = event.event_data["job_type"].as_str().unwrap_or("unknown");
                let payment_amount = event.event_data["payment_amount"].as_str().unwrap_or("0");
                let priority = event.event_data["priority"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(5);
                
                sqlx::query(
                    r#"
                    INSERT INTO jobs (job_id, client_address, job_type, status, priority, payment_amount, tx_hash, block_number)
                    VALUES ($1, $2, $3, 'pending', $4, $5::numeric, $6, $7)
                    ON CONFLICT (job_id) DO UPDATE SET
                        client_address = EXCLUDED.client_address,
                        job_type = EXCLUDED.job_type,
                        payment_amount = EXCLUDED.payment_amount
                    "#
                )
                .bind(job_id)
                .bind(client)
                .bind(job_type)
                .bind(priority)
                .bind(payment_amount)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "JobAssigned" => {
                let job_id = event.event_data["job_id"].as_str().unwrap_or("0");
                let worker = event.event_data["worker"].as_str().unwrap_or("0");
                
                sqlx::query(
                    "UPDATE jobs SET worker_address = $1, status = 'assigned', assigned_at = NOW() WHERE job_id = $2"
                )
                .bind(worker)
                .bind(job_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "JobCompleted" => {
                let job_id = event.event_data["job_id"].as_str().unwrap_or("0");
                let result_hash = event.event_data["result_hash"].as_str().unwrap_or("0");
                let execution_time = event.event_data["execution_time_ms"].as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                
                sqlx::query(
                    r#"
                    UPDATE jobs SET 
                        status = 'completed', 
                        completed_at = NOW(), 
                        result_hash = $1,
                        execution_time_ms = $2
                    WHERE job_id = $3
                    "#
                )
                .bind(result_hash)
                .bind(execution_time)
                .bind(job_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "JobCancelled" => {
                let job_id = event.event_data["job_id"].as_str().unwrap_or("0");
                let reason = event.event_data["reason"].as_str().unwrap_or("");
                
                sqlx::query(
                    "UPDATE jobs SET status = 'cancelled', cancelled_at = NOW(), error_message = $1 WHERE job_id = $2"
                )
                .bind(reason)
                .bind(job_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "PaymentReleased" => {
                let job_id = event.event_data["job_id"].as_str().unwrap_or("0");
                let worker = event.event_data["worker"].as_str().unwrap_or("0");
                let amount = event.event_data["amount"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    INSERT INTO payments (job_id, worker_address, amount, payment_type, tx_hash, block_number)
                    VALUES ($1, $2, $3::numeric, 'job_completion', $4, $5)
                    "#
                )
                .bind(job_id)
                .bind(worker)
                .bind(amount)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Handle Staking events
    async fn handle_staking_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        let worker = event.event_data["worker"].as_str().unwrap_or("0");
        let amount = event.event_data["amount"].as_str().unwrap_or("0");
        
        // Record staking event
        sqlx::query(
            r#"
            INSERT INTO staking_events (worker_id, worker_address, event_type, amount, gpu_tier, has_tee, tx_hash, block_number)
            VALUES ($1, $2, $3, $4::numeric, $5, $6, $7, $8)
            "#
        )
        .bind(worker)
        .bind(worker)
        .bind(&event.event_name)
        .bind(amount)
        .bind(event.event_data["gpu_tier"].as_str())
        .bind(event.event_data["has_tee"].as_bool().unwrap_or(false))
        .bind(&event.transaction_hash)
        .bind(event.block_number as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
        
        // Update worker record
        match event.event_name.as_str() {
            "Staked" => {
                let gpu_tier = event.event_data["gpu_tier"].as_str();
                let has_tee = event.event_data["has_tee"].as_bool().unwrap_or(false);
                
                sqlx::query(
                    r#"
                    INSERT INTO workers (worker_id, address, status, staked_amount, gpu_tier, has_tee, tx_hash, block_number)
                    VALUES ($1, $2, 'active', $3::numeric, $4, $5, $6, $7)
                    ON CONFLICT (address) DO UPDATE SET
                        staked_amount = workers.staked_amount + $3::numeric,
                        status = 'active',
                        gpu_tier = COALESCE($4, workers.gpu_tier),
                        has_tee = COALESCE($5, workers.has_tee)
                    "#
                )
                .bind(worker)
                .bind(worker)
                .bind(amount)
                .bind(gpu_tier)
                .bind(has_tee)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "Unstaked" | "UnstakeInitiated" => {
                sqlx::query(
                    "UPDATE workers SET staked_amount = staked_amount - $1::numeric WHERE address = $2"
                )
                .bind(amount)
                .bind(worker)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "Slashed" => {
                sqlx::query(
                    r#"
                    UPDATE workers SET 
                        staked_amount = staked_amount - $1::numeric,
                        reputation_score = GREATEST(0, reputation_score - 10)
                    WHERE address = $2
                    "#
                )
                .bind(amount)
                .bind(worker)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Handle OTC Orderbook events
    async fn handle_otc_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "OrderPlaced" => {
                let order_id = event.event_data["order_id"].as_str().unwrap_or("0");
                let maker = event.event_data["maker"].as_str().unwrap_or("0");
                let pair_id = event.event_data["pair_id"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let side_raw = event.event_data["side"].as_str().unwrap_or("0");
                let side = if side_raw == "1" || side_raw == "0x1" { "sell" } else { "buy" };
                let price = event.event_data["price"].as_str().unwrap_or("0");
                let amount = event.event_data["amount"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    INSERT INTO orders (order_id, pair_id, maker_address, side, price, original_amount, remaining_amount, status, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, $5::numeric, $6::numeric, $6::numeric, 'open', $7, $8)
                    ON CONFLICT (order_id) DO NOTHING
                    "#
                )
                .bind(order_id)
                .bind(pair_id)
                .bind(maker)
                .bind(side)
                .bind(price)
                .bind(amount)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "OrderFilled" => {
                let order_id = event.event_data["order_id"].as_str().unwrap_or("0");
                let filled_amount = event.event_data["filled_amount"].as_str().unwrap_or("0");
                let remaining = event.event_data["remaining_amount"].as_str().unwrap_or("0");
                
                let status = if remaining == "0" { "filled" } else { "partial" };
                
                sqlx::query(
                    r#"
                    UPDATE orders SET 
                        filled_amount = filled_amount + $1::numeric,
                        remaining_amount = $2::numeric,
                        status = $3,
                        updated_at = NOW()
                    WHERE order_id = $4
                    "#
                )
                .bind(filled_amount)
                .bind(remaining)
                .bind(status)
                .bind(order_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "OrderCancelled" => {
                let order_id = event.event_data["order_id"].as_str().unwrap_or("0");
                
                sqlx::query(
                    "UPDATE orders SET status = 'cancelled', updated_at = NOW() WHERE order_id = $1"
                )
                .bind(order_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "TradeExecuted" => {
                let trade_id = event.event_data["trade_id"].as_str().unwrap_or("0");
                let maker_order_id = event.event_data["maker_order_id"].as_str().unwrap_or("0");
                let taker_order_id = event.event_data["taker_order_id"].as_str();
                let pair_id = event.event_data["pair_id"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(1); // Default to SAGE_STRK (pair_id 1)
                let maker = event.event_data["maker"].as_str().unwrap_or("0");
                let taker = event.event_data["taker"].as_str().unwrap_or("0");
                let price = event.event_data["price"].as_str().unwrap_or("0");
                let amount = event.event_data["amount"].as_str().unwrap_or("0");
                let quote_amount = event.event_data["quote_amount"].as_str().unwrap_or("0");
                let maker_fee = event.event_data["maker_fee"].as_str().unwrap_or("0");
                let taker_fee = event.event_data["taker_fee"].as_str().unwrap_or("0");
                let side = event.event_data["side"].as_str().unwrap_or("buy");

                sqlx::query(
                    r#"
                    INSERT INTO trades (trade_id, pair_id, maker_order_id, taker_order_id, maker_address, taker_address, side, price, amount, quote_amount, maker_fee, taker_fee, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::numeric, $9::numeric, $10::numeric, $11::numeric, $12::numeric, $13, $14)
                    ON CONFLICT (trade_id) DO NOTHING
                    "#
                )
                .bind(trade_id)
                .bind(pair_id)
                .bind(maker_order_id)
                .bind(taker_order_id)
                .bind(maker)
                .bind(taker)
                .bind(side)
                .bind(price)
                .bind(amount)
                .bind(quote_amount)
                .bind(maker_fee)
                .bind(taker_fee)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;

                info!("Indexed trade {}: {} {} at price {}", trade_id, amount, if side == "buy" { "bought" } else { "sold" }, price);
            }
            "PairAdded" => {
                let pair_id = event.event_data["pair_id"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let base_token = event.event_data["base_token"].as_str().unwrap_or("0");
                let quote_token = event.event_data["quote_token"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    INSERT INTO trading_pairs (pair_id, base_token, quote_token, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (pair_id) DO NOTHING
                    "#
                )
                .bind(pair_id)
                .bind(base_token)
                .bind(quote_token)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Handle Governance events
    async fn handle_governance_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "ProposalCreated" => {
                let proposal_id = event.event_data["proposal_id"].as_str().unwrap_or("0");
                let proposer = event.event_data["proposer"].as_str().unwrap_or("0");
                let proposal_type = event.event_data["proposal_type"].as_str().unwrap_or("general");
                let start_block = event.event_data["start_block"].as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                let end_block = event.event_data["end_block"].as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                
                sqlx::query(
                    r#"
                    INSERT INTO proposals (proposal_id, proposer_address, title, proposal_type, status, start_block, end_block, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8)
                    ON CONFLICT (proposal_id) DO NOTHING
                    "#
                )
                .bind(proposal_id)
                .bind(proposer)
                .bind(format!("Proposal {}", proposal_id))
                .bind(proposal_type)
                .bind(start_block)
                .bind(end_block)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "VoteCast" => {
                let proposal_id = event.event_data["proposal_id"].as_str().unwrap_or("0");
                let voter = event.event_data["voter"].as_str().unwrap_or("0");
                let support = event.event_data["support"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let voting_power = event.event_data["voting_power"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    INSERT INTO votes (proposal_id, voter_address, support, voting_power, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4::numeric, $5, $6)
                    ON CONFLICT (proposal_id, voter_address) DO UPDATE SET
                        support = EXCLUDED.support,
                        voting_power = EXCLUDED.voting_power
                    "#
                )
                .bind(proposal_id)
                .bind(voter)
                .bind(support)
                .bind(voting_power)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
                
                // Update proposal vote counts
                let vote_column = match support {
                    0 => "against_votes",
                    1 => "for_votes",
                    _ => "abstain_votes",
                };
                
                sqlx::query(&format!(
                    "UPDATE proposals SET {} = {} + $1::numeric WHERE proposal_id = $2",
                    vote_column, vote_column
                ))
                .bind(voting_power)
                .bind(proposal_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "ProposalExecuted" => {
                let proposal_id = event.event_data["proposal_id"].as_str().unwrap_or("0");
                
                sqlx::query(
                    "UPDATE proposals SET status = 'executed', executed_at = NOW() WHERE proposal_id = $1"
                )
                .bind(proposal_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "ProposalCancelled" => {
                let proposal_id = event.event_data["proposal_id"].as_str().unwrap_or("0");
                
                sqlx::query(
                    "UPDATE proposals SET status = 'cancelled' WHERE proposal_id = $1"
                )
                .bind(proposal_id)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Handle Privacy Router events
    async fn handle_privacy_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "PrivateTransferInitiated" => {
                let nullifier = event.event_data["nullifier"].as_str().unwrap_or("0");
                let sender = event.event_data["sender"].as_str();
                let encrypted_amount = event.event_data["encrypted_amount"].as_str().unwrap_or("0");
                let commitment = event.event_data["commitment"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    INSERT INTO private_transfers (nullifier, sender_address, encrypted_amount, commitment, status, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, 'pending', $5, $6)
                    ON CONFLICT (nullifier) DO NOTHING
                    "#
                )
                .bind(nullifier)
                .bind(sender)
                .bind(encrypted_amount)
                .bind(commitment)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "PrivateTransferCompleted" => {
                let nullifier = event.event_data["nullifier"].as_str().unwrap_or("0");
                
                sqlx::query(
                    "UPDATE private_transfers SET status = 'completed', completed_at = NOW() WHERE nullifier = $1"
                )
                .bind(nullifier)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "StealthAddressRegistered" => {
                let owner = event.event_data["owner"].as_str().unwrap_or("0");
                let stealth_address = event.event_data["stealth_address"].as_str().unwrap_or("0");
                let ephemeral_pubkey = event.event_data["ephemeral_pubkey"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    INSERT INTO stealth_addresses (owner_address, stealth_address, ephemeral_pubkey, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (stealth_address) DO NOTHING
                    "#
                )
                .bind(owner)
                .bind(stealth_address)
                .bind(ephemeral_pubkey)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Handle Proof Verifier events
    async fn handle_proof_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "ProofVerified" => {
                let job_id = event.event_data["job_id"].as_str().unwrap_or("0");
                let worker = event.event_data["worker"].as_str().unwrap_or("0");
                let proof_hash = event.event_data["proof_hash"].as_str().unwrap_or("0");
                let is_valid = event.event_data["is_valid"].as_bool().unwrap_or(false);
                let verification_time = event.event_data["verification_time_ms"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                
                sqlx::query(
                    r#"
                    INSERT INTO proofs (job_id, worker_id, proof_hash, is_valid, verification_time_ms, verified_at, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)
                    ON CONFLICT DO NOTHING
                    "#
                )
                .bind(job_id)
                .bind(worker)
                .bind(proof_hash)
                .bind(is_valid)
                .bind(verification_time)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Handle Reputation events
    async fn handle_reputation_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "ReputationUpdated" => {
                let worker = event.event_data["worker"].as_str().unwrap_or("0");
                let new_score = event.event_data["new_score"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(100);
                
                sqlx::query(
                    "UPDATE workers SET reputation_score = $1 WHERE address = $2"
                )
                .bind(new_score)
                .bind(worker)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "WorkerRegistered" => {
                let worker = event.event_data["worker"].as_str().unwrap_or("0");
                let initial_score = event.event_data["initial_score"].as_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(100);
                
                sqlx::query(
                    r#"
                    INSERT INTO workers (worker_id, address, status, reputation_score, tx_hash, block_number)
                    VALUES ($1, $2, 'registered', $3, $4, $5)
                    ON CONFLICT (address) DO UPDATE SET reputation_score = EXCLUDED.reputation_score
                    "#
                )
                .bind(worker)
                .bind(worker)
                .bind(initial_score)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Handle Referral events
    async fn handle_referral_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "ReferrerRegistered" => {
                let referrer = event.event_data["referrer"].as_str().unwrap_or("0");
                let code = event.event_data["code"].as_str().unwrap_or("");
                
                sqlx::query(
                    r#"
                    INSERT INTO referrers (address, referral_code, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (address) DO NOTHING
                    "#
                )
                .bind(referrer)
                .bind(code)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "ReferralRecorded" => {
                let referrer = event.event_data["referrer"].as_str().unwrap_or("0");
                let referred = event.event_data["referred"].as_str().unwrap_or("0");
                let code = event.event_data["code"].as_str().unwrap_or("");
                
                sqlx::query(
                    r#"
                    INSERT INTO referrals (referrer_address, referred_address, referral_code, tx_hash, block_number)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (referred_address) DO NOTHING
                    "#
                )
                .bind(referrer)
                .bind(referred)
                .bind(code)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            "CommissionPaid" => {
                let referrer = event.event_data["referrer"].as_str().unwrap_or("0");
                let amount = event.event_data["amount"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    UPDATE referrers SET 
                        total_rewards = total_rewards + $1::numeric,
                        updated_at = NOW()
                    WHERE address = $2
                    "#
                )
                .bind(amount)
                .bind(referrer)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Handle Faucet events
    async fn handle_faucet_event(&self, event: &ProcessedEvent) -> Result<(), IndexerError> {
        match event.event_name.as_str() {
            "Claimed" => {
                let claimer = event.event_data["claimer"].as_str().unwrap_or("0");
                let amount = event.event_data["amount"].as_str().unwrap_or("0");
                
                sqlx::query(
                    r#"
                    INSERT INTO faucet_claims (claimer_address, amount, tx_hash, block_number)
                    VALUES ($1, $2::numeric, $3, $4)
                    "#
                )
                .bind(claimer)
                .bind(amount)
                .bind(&event.transaction_hash)
                .bind(event.block_number as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Update indexer state for a contract
    pub async fn update_indexer_state(&self, block_number: u64) -> Result<(), IndexerError> {
        sqlx::query(
            r#"
            UPDATE indexer_state SET 
                last_indexed_block = $1,
                last_indexed_at = NOW(),
                updated_at = NOW()
            WHERE last_indexed_block < $1
            "#
        )
        .bind(block_number as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Get the last indexed block for a contract
    pub async fn get_last_indexed_block(&self, contract_name: &str) -> Result<u64, IndexerError> {
        let row = sqlx::query(
            "SELECT last_indexed_block FROM indexer_state WHERE contract_name = $1"
        )
        .bind(contract_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.get::<i64, _>("last_indexed_block") as u64).unwrap_or(0))
    }

    /// Get the minimum indexed block across all contracts (for resuming indexer)
    pub async fn get_min_indexed_block(&self) -> Result<Option<u64>, IndexerError> {
        let row = sqlx::query(
            "SELECT MIN(last_indexed_block) as min_block FROM indexer_state WHERE last_indexed_block > 0"
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;

        Ok(row.and_then(|r| r.try_get::<i64, _>("min_block").ok()).map(|b| b as u64))
    }
    
    /// Take a network stats snapshot
    pub async fn take_stats_snapshot(&self) -> Result<(), IndexerError> {
        sqlx::query(
            r#"
            INSERT INTO network_stats_snapshots (
                total_workers, active_workers, total_jobs, jobs_24h, jobs_completed_24h,
                total_staked, total_volume_24h, avg_job_time_ms
            )
            SELECT
                (SELECT COUNT(*) FROM workers),
                (SELECT COUNT(*) FROM workers WHERE status = 'active'),
                (SELECT COUNT(*) FROM jobs),
                (SELECT COUNT(*) FROM jobs WHERE created_at > NOW() - INTERVAL '24 hours'),
                (SELECT COUNT(*) FROM jobs WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '24 hours'),
                (SELECT COALESCE(SUM(staked_amount), 0) FROM workers),
                (SELECT COALESCE(SUM(quote_amount), 0) FROM trades WHERE executed_at > NOW() - INTERVAL '24 hours'),
                (SELECT AVG(execution_time_ms) FROM jobs WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '24 hours')
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(|e| IndexerError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Integration tests would require a test database
    #[test]
    fn test_db_writer_types() {
        // Type check only - actual DB tests need integration setup
        let _ = ProcessedEvent {
            contract_name: "JobManager".to_string(),
            contract_address: "0x123".to_string(),
            event_name: "JobSubmitted".to_string(),
            event_data: serde_json::json!({}),
            block_number: 100,
            block_timestamp: None,
            transaction_hash: "0x456".to_string(),
            log_index: None,
        };
    }
}
