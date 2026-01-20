//! # WebSocket API for Real-time Updates
//!
//! Provides WebSocket endpoint for streaming job updates, worker events,
//! network status, and indexed blockchain events to connected clients.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// WebSocket event types - Extended for indexed events
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsEvent {
    // ===== Core Events =====
    /// Job status changed
    JobUpdate(JobUpdateEvent),
    /// Worker status changed
    WorkerUpdate(WorkerUpdateEvent),
    /// Network statistics updated
    NetworkStats(NetworkStatsEvent),
    /// Proof verification completed
    ProofVerified(ProofVerifiedEvent),

    // ===== Indexed Blockchain Events =====
    /// Staking event from blockchain
    StakingEvent(StakingWsEvent),
    /// OTC Order placed
    OrderPlaced(OrderWsEvent),
    /// OTC Order filled/cancelled
    OrderUpdated(OrderUpdateWsEvent),
    /// Trade executed
    TradeExecuted(TradeWsEvent),
    /// Governance proposal created
    ProposalCreated(ProposalWsEvent),
    /// Vote cast on proposal
    VoteCast(VoteWsEvent),
    /// Privacy transfer event
    PrivacyEvent(PrivacyWsEvent),
    /// Faucet claim
    FaucetClaim(FaucetWsEvent),
    /// Generic indexed event (for new event types)
    IndexedEvent(IndexedWsEvent),

    // ===== System Events =====
    /// Heartbeat to keep connection alive
    Heartbeat { timestamp: u64 },
    /// Error occurred
    Error { message: String },
    /// Subscription confirmed
    Subscribed { channels: Vec<String> },
}

/// Job update event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobUpdateEvent {
    pub job_id: String,
    pub status: String,
    pub progress: Option<f32>,
    pub worker_id: Option<String>,
    pub result_hash: Option<String>,
    pub error: Option<String>,
    pub timestamp: u64,
}

/// Worker update event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerUpdateEvent {
    pub worker_id: String,
    pub status: String,
    pub gpu_utilization: Option<f32>,
    pub memory_used_mb: Option<u64>,
    pub jobs_active: u32,
    pub timestamp: u64,
}

/// Network statistics event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkStatsEvent {
    pub total_workers: u32,
    pub active_workers: u32,
    pub total_jobs: u64,
    pub jobs_in_progress: u32,
    pub jobs_completed_24h: u64,
    pub network_tps: f32,
    pub timestamp: u64,
}

/// Proof verified event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofVerifiedEvent {
    pub job_id: String,
    pub proof_hash: String,
    pub verifier: String,
    pub is_valid: bool,
    pub gas_used: u64,
    pub timestamp: u64,
}

// ===== Indexed Blockchain Event Types =====

/// Staking WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakingWsEvent {
    pub worker_address: String,
    pub event_type: String, // "stake", "unstake", "slashed"
    pub amount: String,
    pub gpu_tier: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Order placed WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderWsEvent {
    pub order_id: String,
    pub maker_address: String,
    pub pair_id: u32,
    pub side: String, // "buy" or "sell"
    pub price: String,
    pub amount: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Order update WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderUpdateWsEvent {
    pub order_id: String,
    pub status: String, // "filled", "partial", "cancelled"
    pub filled_amount: Option<String>,
    pub remaining_amount: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Trade executed WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TradeWsEvent {
    pub trade_id: String,
    pub pair_id: u32,
    pub maker_address: String,
    pub taker_address: String,
    pub price: String,
    pub amount: String,
    pub side: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Proposal WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalWsEvent {
    pub proposal_id: String,
    pub proposer_address: String,
    pub proposal_type: String,
    pub title: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Vote cast WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteWsEvent {
    pub proposal_id: String,
    pub voter_address: String,
    pub support: u8, // 0 = against, 1 = for, 2 = abstain
    pub voting_power: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Privacy WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyWsEvent {
    pub event_type: String, // "transfer_initiated", "transfer_completed", "deposit", "withdrawal"
    pub nullifier: Option<String>,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Faucet WebSocket event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetWsEvent {
    pub claimer_address: String,
    pub amount: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// Generic indexed event for extensibility
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedWsEvent {
    pub contract_name: String,
    pub event_name: String,
    pub event_data: serde_json::Value,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: u64,
}

/// WebSocket state shared between handlers
pub struct WebSocketState {
    /// Broadcast channel for events
    pub event_tx: broadcast::Sender<WsEvent>,
}

impl WebSocketState {
    pub fn new(capacity: usize) -> Self {
        let (event_tx, _) = broadcast::channel(capacity);
        Self { event_tx }
    }

    /// Broadcast an event to all connected clients
    pub fn broadcast(&self, event: WsEvent) {
        if let Err(e) = self.event_tx.send(event) {
            debug!("No WebSocket subscribers to broadcast to: {}", e);
        }
    }

    /// Get number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.event_tx.receiver_count()
    }

    // ===== Helper methods for broadcasting indexed events =====

    /// Broadcast a job update from indexed event
    pub fn broadcast_job_update(&self, job_id: String, status: String, worker_id: Option<String>, result_hash: Option<String>) {
        self.broadcast(WsEvent::JobUpdate(JobUpdateEvent {
            job_id,
            status,
            progress: None,
            worker_id,
            result_hash,
            error: None,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a staking event
    pub fn broadcast_staking(&self, worker_address: String, event_type: String, amount: String, gpu_tier: Option<String>, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::StakingEvent(StakingWsEvent {
            worker_address,
            event_type,
            amount,
            gpu_tier,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast an order placed event
    pub fn broadcast_order_placed(&self, order_id: String, maker_address: String, pair_id: u32, side: String, price: String, amount: String, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::OrderPlaced(OrderWsEvent {
            order_id,
            maker_address,
            pair_id,
            side,
            price,
            amount,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast an order update event
    pub fn broadcast_order_update(&self, order_id: String, status: String, filled_amount: Option<String>, remaining_amount: Option<String>, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::OrderUpdated(OrderUpdateWsEvent {
            order_id,
            status,
            filled_amount,
            remaining_amount,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a trade executed event
    pub fn broadcast_trade(&self, trade_id: String, pair_id: u32, maker_address: String, taker_address: String, price: String, amount: String, side: String, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::TradeExecuted(TradeWsEvent {
            trade_id,
            pair_id,
            maker_address,
            taker_address,
            price,
            amount,
            side,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a proposal created event
    pub fn broadcast_proposal(&self, proposal_id: String, proposer_address: String, proposal_type: String, title: Option<String>, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::ProposalCreated(ProposalWsEvent {
            proposal_id,
            proposer_address,
            proposal_type,
            title,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a vote cast event
    pub fn broadcast_vote(&self, proposal_id: String, voter_address: String, support: u8, voting_power: String, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::VoteCast(VoteWsEvent {
            proposal_id,
            voter_address,
            support,
            voting_power,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a privacy event
    pub fn broadcast_privacy(&self, event_type: String, nullifier: Option<String>, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::PrivacyEvent(PrivacyWsEvent {
            event_type,
            nullifier,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a faucet claim event
    pub fn broadcast_faucet_claim(&self, claimer_address: String, amount: String, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::FaucetClaim(FaucetWsEvent {
            claimer_address,
            amount,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a generic indexed event
    pub fn broadcast_indexed(&self, contract_name: String, event_name: String, event_data: serde_json::Value, tx_hash: String, block_number: u64) {
        self.broadcast(WsEvent::IndexedEvent(IndexedWsEvent {
            contract_name,
            event_name,
            event_data,
            tx_hash,
            block_number,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a proof verified event
    pub fn broadcast_proof_verified(&self, job_id: String, proof_hash: String, verifier: String, is_valid: bool, gas_used: u64) {
        self.broadcast(WsEvent::ProofVerified(ProofVerifiedEvent {
            job_id,
            proof_hash,
            verifier,
            is_valid,
            gas_used,
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast a worker status update (from heartbeats)
    pub fn broadcast_worker_update(&self, worker_id: String, status: String, gpu_count: Option<u32>, gpu_utilization: Option<f32>) {
        self.broadcast(WsEvent::WorkerUpdate(WorkerUpdateEvent {
            worker_id,
            status,
            gpu_utilization,
            memory_used_mb: None,
            jobs_active: gpu_count.unwrap_or(0),
            timestamp: current_timestamp(),
        }));
    }

    /// Broadcast network statistics update
    pub fn broadcast_network_stats(
        &self,
        total_workers: u32,
        active_workers: u32,
        total_jobs: u64,
        jobs_in_progress: u32,
        jobs_completed_24h: u64,
        network_tps: f32,
    ) {
        self.broadcast(WsEvent::NetworkStats(NetworkStatsEvent {
            total_workers,
            active_workers,
            total_jobs,
            jobs_in_progress,
            jobs_completed_24h,
            network_tps,
            timestamp: current_timestamp(),
        }));
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Query parameters for WebSocket subscriptions
#[derive(Debug, Deserialize)]
pub struct WsQueryParams {
    /// Filter by specific address (for staking, orders, etc.)
    pub address: Option<String>,
    /// Filter by pair_id (for trading)
    pub pair_id: Option<u32>,
    /// Filter by proposal_id (for governance)
    pub proposal_id: Option<String>,
}

/// Create WebSocket routes
pub fn websocket_routes(state: Arc<WebSocketState>) -> Router {
    Router::new()
        // Core endpoints
        .route("/ws", get(ws_handler))
        .route("/ws/jobs", get(ws_jobs_handler))
        .route("/ws/workers", get(ws_workers_handler))
        // Indexed event endpoints
        .route("/ws/trading", get(ws_trading_handler))
        .route("/ws/staking", get(ws_staking_handler))
        .route("/ws/governance", get(ws_governance_handler))
        .route("/ws/privacy", get(ws_privacy_handler))
        .route("/ws/proofs", get(ws_proofs_handler))
        .with_state(state)
}

/// Main WebSocket handler - receives all events
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state, None))
}

/// Job-specific WebSocket handler
async fn ws_jobs_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state, Some(EventFilter::Jobs)))
}

/// Worker-specific WebSocket handler
async fn ws_workers_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state, Some(EventFilter::Workers)))
}

/// Trading WebSocket handler - order book updates, trades
async fn ws_trading_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
    Query(params): Query<WsQueryParams>,
) -> impl IntoResponse {
    info!("Trading WebSocket connection (pair_id: {:?})", params.pair_id);
    ws.on_upgrade(move |socket| handle_socket_with_params(socket, state, EventFilter::Trading, params))
}

/// Staking WebSocket handler - stake/unstake events
async fn ws_staking_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
    Query(params): Query<WsQueryParams>,
) -> impl IntoResponse {
    info!("Staking WebSocket connection (address: {:?})", params.address);
    ws.on_upgrade(move |socket| handle_socket_with_params(socket, state, EventFilter::Staking, params))
}

/// Governance WebSocket handler - proposals, votes
async fn ws_governance_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
    Query(params): Query<WsQueryParams>,
) -> impl IntoResponse {
    info!("Governance WebSocket connection (proposal_id: {:?})", params.proposal_id);
    ws.on_upgrade(move |socket| handle_socket_with_params(socket, state, EventFilter::Governance, params))
}

/// Privacy WebSocket handler - private transfers
async fn ws_privacy_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
    Query(params): Query<WsQueryParams>,
) -> impl IntoResponse {
    info!("Privacy WebSocket connection (address: {:?})", params.address);
    ws.on_upgrade(move |socket| handle_socket_with_params(socket, state, EventFilter::Privacy, params))
}

/// Proofs WebSocket handler - proof verifications
async fn ws_proofs_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state, Some(EventFilter::Proofs)))
}

/// Event filter for specific WebSocket endpoints
#[derive(Clone, Copy, Debug)]
enum EventFilter {
    /// Core job events
    Jobs,
    /// Worker status events
    Workers,
    /// OTC trading events (orders, trades)
    Trading,
    /// Staking events (stake, unstake, slash)
    Staking,
    /// Governance events (proposals, votes)
    Governance,
    /// Privacy events (transfers, deposits)
    Privacy,
    /// Proof verification events
    Proofs,
}

impl EventFilter {
    fn matches(&self, event: &WsEvent) -> bool {
        match self {
            EventFilter::Jobs => matches!(
                event,
                WsEvent::JobUpdate(_) | WsEvent::Heartbeat { .. }
            ),
            EventFilter::Workers => matches!(
                event,
                WsEvent::WorkerUpdate(_) | WsEvent::NetworkStats(_) | WsEvent::Heartbeat { .. }
            ),
            EventFilter::Trading => matches!(
                event,
                WsEvent::OrderPlaced(_) | WsEvent::OrderUpdated(_) | WsEvent::TradeExecuted(_) | WsEvent::Heartbeat { .. }
            ),
            EventFilter::Staking => matches!(
                event,
                WsEvent::StakingEvent(_) | WsEvent::Heartbeat { .. }
            ),
            EventFilter::Governance => matches!(
                event,
                WsEvent::ProposalCreated(_) | WsEvent::VoteCast(_) | WsEvent::Heartbeat { .. }
            ),
            EventFilter::Privacy => matches!(
                event,
                WsEvent::PrivacyEvent(_) | WsEvent::Heartbeat { .. }
            ),
            EventFilter::Proofs => matches!(
                event,
                WsEvent::ProofVerified(_) | WsEvent::Heartbeat { .. }
            ),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            EventFilter::Jobs => "jobs",
            EventFilter::Workers => "workers",
            EventFilter::Trading => "trading",
            EventFilter::Staking => "staking",
            EventFilter::Governance => "governance",
            EventFilter::Privacy => "privacy",
            EventFilter::Proofs => "proofs",
        }
    }
}

/// Handle a WebSocket connection with query parameter filtering
async fn handle_socket_with_params(
    socket: WebSocket,
    state: Arc<WebSocketState>,
    filter: EventFilter,
    params: WsQueryParams,
) {
    let (mut sender, mut receiver) = socket.split();
    let mut event_rx = state.event_tx.subscribe();

    info!(
        "New WebSocket connection (filter: {}, address: {:?}, pair_id: {:?}, total subscribers: {})",
        filter.as_str(),
        params.address,
        params.pair_id,
        state.subscriber_count()
    );

    // Spawn task to send events to client
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = event_rx.recv() => {
                    match result {
                        Ok(event) => {
                            // Apply event type filter
                            if !filter.matches(&event) {
                                continue;
                            }

                            // Apply address filter for relevant events
                            if let Some(ref addr) = params.address {
                                if !event_matches_address(&event, addr) {
                                    continue;
                                }
                            }

                            // Apply pair_id filter for trading events
                            if let Some(pair) = params.pair_id {
                                if !event_matches_pair(&event, pair) {
                                    continue;
                                }
                            }

                            // Apply proposal_id filter for governance events
                            if let Some(ref proposal) = params.proposal_id {
                                if !event_matches_proposal(&event, proposal) {
                                    continue;
                                }
                            }

                            // Serialize and send
                            match serde_json::to_string(&event) {
                                Ok(json) => {
                                    if let Err(e) = sender.send(Message::Text(json)).await {
                                        error!("Failed to send WebSocket message: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to serialize event: {}", e);
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WebSocket client lagged, dropped {} messages", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!("Event channel closed");
                            break;
                        }
                    }
                }

                // Send heartbeat every 30 seconds
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    let heartbeat = WsEvent::Heartbeat {
                        timestamp: current_timestamp(),
                    };
                    if let Ok(json) = serde_json::to_string(&heartbeat) {
                        if let Err(e) = sender.send(Message::Text(json)).await {
                            debug!("Failed to send heartbeat: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    // Handle incoming messages from client
    while let Some(result) = receiver.next().await {
        match result {
            Ok(Message::Text(text)) => {
                debug!("Received text message: {}", text);
            }
            Ok(Message::Ping(_)) => {
                debug!("Received ping");
            }
            Ok(Message::Close(_)) => {
                debug!("Client closed connection");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    send_task.abort();
    info!("WebSocket connection closed (filter: {})", filter.as_str());
}

/// Check if event matches the specified address filter
fn event_matches_address(event: &WsEvent, address: &str) -> bool {
    match event {
        WsEvent::StakingEvent(e) => e.worker_address.eq_ignore_ascii_case(address),
        WsEvent::OrderPlaced(e) => e.maker_address.eq_ignore_ascii_case(address),
        WsEvent::OrderUpdated(_) => true, // Order updates don't have address, show all
        WsEvent::TradeExecuted(e) => {
            e.maker_address.eq_ignore_ascii_case(address) ||
            e.taker_address.eq_ignore_ascii_case(address)
        }
        WsEvent::VoteCast(e) => e.voter_address.eq_ignore_ascii_case(address),
        WsEvent::FaucetClaim(e) => e.claimer_address.eq_ignore_ascii_case(address),
        WsEvent::Heartbeat { .. } => true, // Always pass heartbeats
        _ => true, // Default to showing unfiltered events
    }
}

/// Check if event matches the specified pair_id filter
fn event_matches_pair(event: &WsEvent, pair_id: u32) -> bool {
    match event {
        WsEvent::OrderPlaced(e) => e.pair_id == pair_id,
        WsEvent::TradeExecuted(e) => e.pair_id == pair_id,
        WsEvent::Heartbeat { .. } => true,
        _ => true,
    }
}

/// Check if event matches the specified proposal_id filter
fn event_matches_proposal(event: &WsEvent, proposal_id: &str) -> bool {
    match event {
        WsEvent::ProposalCreated(e) => e.proposal_id.eq_ignore_ascii_case(proposal_id),
        WsEvent::VoteCast(e) => e.proposal_id.eq_ignore_ascii_case(proposal_id),
        WsEvent::Heartbeat { .. } => true,
        _ => true,
    }
}

/// Handle a WebSocket connection
async fn handle_socket(
    socket: WebSocket,
    state: Arc<WebSocketState>,
    filter: Option<EventFilter>,
) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to events
    let mut event_rx = state.event_tx.subscribe();

    info!(
        "New WebSocket connection (filter: {:?}, total subscribers: {})",
        filter.map(|f| f.as_str()),
        state.subscriber_count()
    );

    // Spawn task to send events to client
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Receive broadcast events
                result = event_rx.recv() => {
                    match result {
                        Ok(event) => {
                            // Apply filter if set
                            if let Some(ref f) = filter {
                                if !f.matches(&event) {
                                    continue;
                                }
                            }

                            // Serialize and send
                            match serde_json::to_string(&event) {
                                Ok(json) => {
                                    if let Err(e) = sender.send(Message::Text(json)).await {
                                        error!("Failed to send WebSocket message: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to serialize event: {}", e);
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WebSocket client lagged, dropped {} messages", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!("Event channel closed");
                            break;
                        }
                    }
                }

                // Send heartbeat every 30 seconds
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    let heartbeat = WsEvent::Heartbeat {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    };
                    if let Ok(json) = serde_json::to_string(&heartbeat) {
                        if let Err(e) = sender.send(Message::Text(json)).await {
                            debug!("Failed to send heartbeat: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    // Handle incoming messages from client
    while let Some(result) = receiver.next().await {
        match result {
            Ok(Message::Text(text)) => {
                debug!("Received text message: {}", text);
                // Could handle subscription messages here
            }
            Ok(Message::Ping(data)) => {
                debug!("Received ping");
                // axum handles pong automatically
                let _ = data;
            }
            Ok(Message::Close(_)) => {
                debug!("Client closed connection");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    send_task.abort();
    info!("WebSocket connection closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = WsEvent::JobUpdate(JobUpdateEvent {
            job_id: "job-123".to_string(),
            status: "running".to_string(),
            progress: Some(0.5),
            worker_id: Some("worker-1".to_string()),
            result_hash: None,
            error: None,
            timestamp: 1234567890,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("JobUpdate"));
        assert!(json.contains("job-123"));
    }

    #[test]
    fn test_event_filter() {
        let job_filter = EventFilter::Jobs;
        let worker_filter = EventFilter::Workers;

        let job_event = WsEvent::JobUpdate(JobUpdateEvent {
            job_id: "test".to_string(),
            status: "done".to_string(),
            progress: None,
            worker_id: None,
            result_hash: None,
            error: None,
            timestamp: 0,
        });

        let worker_event = WsEvent::WorkerUpdate(WorkerUpdateEvent {
            worker_id: "w1".to_string(),
            status: "online".to_string(),
            gpu_utilization: None,
            memory_used_mb: None,
            jobs_active: 0,
            timestamp: 0,
        });

        assert!(job_filter.matches(&job_event));
        assert!(!job_filter.matches(&worker_event));
        assert!(!worker_filter.matches(&job_event));
        assert!(worker_filter.matches(&worker_event));
    }
}
