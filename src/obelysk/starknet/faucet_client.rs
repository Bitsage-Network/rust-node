//! # Faucet Contract Client
//!
//! Client for interacting with the BitSage testnet faucet contract.
//! Provides SAGE token claims for testing purposes.

use anyhow::{anyhow, Context, Result};
use starknet::core::types::FieldElement;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::network::StarknetNetwork;

/// Faucet client configuration
#[derive(Debug, Clone)]
pub struct FaucetClientConfig {
    /// Starknet RPC URL
    pub rpc_url: String,
    /// Faucet contract address
    pub faucet_contract: String,
    /// SAGE token contract address
    pub sage_token_contract: String,
    /// Request timeout
    pub timeout: Duration,
    /// Whether faucet is enabled
    pub enabled: bool,
    /// Claim amount per request (in wei)
    pub claim_amount: u64,
    /// Cooldown period between claims (seconds)
    pub cooldown_secs: u64,
}

impl Default for FaucetClientConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://rpc.starknet-testnet.lava.build".to_string(),
            faucet_contract: "0x0".to_string(),
            sage_token_contract: "0x0".to_string(),
            timeout: Duration::from_secs(30),
            enabled: true,
            claim_amount: 20_000_000_000_000_000, // 0.02 SAGE (18 decimals)
            cooldown_secs: 86400, // 24 hours
        }
    }
}

/// Claim information for an address
#[derive(Debug, Clone)]
pub struct ClaimInfo {
    /// Last claim timestamp
    pub last_claim_at: Option<u64>,
    /// Total amount claimed lifetime
    pub total_claimed: u64,
    /// Number of claims made
    pub claim_count: u32,
}

/// Faucet status for an address
#[derive(Debug, Clone)]
pub struct FaucetStatus {
    /// Whether the address can claim now
    pub can_claim: bool,
    /// Seconds until next claim is available
    pub time_until_next_claim_secs: u64,
    /// Amount that will be claimed
    pub claim_amount: u64,
    /// Total claimed by this address
    pub total_claimed: u64,
}

/// Claim result
#[derive(Debug, Clone)]
pub struct ClaimResult {
    /// Whether claim succeeded
    pub success: bool,
    /// Amount claimed
    pub amount: u64,
    /// Transaction hash
    pub transaction_hash: FieldElement,
    /// New balance after claim
    pub new_balance: Option<u64>,
}

/// Rate limit entry for anti-abuse
#[derive(Debug, Clone)]
struct RateLimitEntry {
    last_request: Instant,
    request_count: u32,
}

/// Faucet contract client
pub struct FaucetClient {
    config: FaucetClientConfig,
    network: StarknetNetwork,
    faucet_contract: FieldElement,
    sage_token_contract: FieldElement,

    // Local cache of claim info (synced from chain periodically)
    claim_cache: Arc<RwLock<HashMap<String, ClaimInfo>>>,

    // Rate limiting by IP (in-memory)
    rate_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
}

impl FaucetClient {
    /// Create a new faucet client
    pub fn new(config: FaucetClientConfig) -> Result<Self> {
        // Determine network from RPC URL
        let network = if config.rpc_url.contains("mainnet") {
            StarknetNetwork::Mainnet
        } else if config.rpc_url.contains("sepolia") {
            StarknetNetwork::Sepolia
        } else if config.rpc_url.contains("localhost") || config.rpc_url.contains("127.0.0.1") {
            StarknetNetwork::Devnet
        } else {
            StarknetNetwork::Custom
        };

        let faucet_contract = FieldElement::from_hex_be(&config.faucet_contract)
            .map_err(|e| anyhow!("Invalid faucet contract address: {}", e))?;

        let sage_token_contract = FieldElement::from_hex_be(&config.sage_token_contract)
            .map_err(|e| anyhow!("Invalid SAGE token contract address: {}", e))?;

        Ok(Self {
            config,
            network,
            faucet_contract,
            sage_token_contract,
            claim_cache: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Check if faucet is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get faucet configuration
    pub fn get_config(&self) -> FaucetConfig {
        FaucetConfig {
            claim_amount: self.config.claim_amount,
            cooldown_secs: self.config.cooldown_secs,
            enabled: self.config.enabled,
        }
    }

    /// Check if an address can claim tokens
    pub async fn can_claim(&self, address: &str) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        let status = self.get_status(address).await?;
        Ok(status.can_claim)
    }

    /// Get time until next claim is available
    pub async fn time_until_claim(&self, address: &str) -> Result<u64> {
        let status = self.get_status(address).await?;
        Ok(status.time_until_next_claim_secs)
    }

    /// Get faucet status for an address
    pub async fn get_status(&self, address: &str) -> Result<FaucetStatus> {
        if !self.config.enabled {
            return Ok(FaucetStatus {
                can_claim: false,
                time_until_next_claim_secs: 0,
                claim_amount: 0,
                total_claimed: 0,
            });
        }

        // Try to get from cache first
        let claim_info = self.get_claim_info(address).await?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (can_claim, time_until) = if let Some(last_claim) = claim_info.last_claim_at {
            let elapsed = now.saturating_sub(last_claim);
            if elapsed >= self.config.cooldown_secs {
                (true, 0)
            } else {
                (false, self.config.cooldown_secs - elapsed)
            }
        } else {
            // Never claimed before
            (true, 0)
        };

        Ok(FaucetStatus {
            can_claim,
            time_until_next_claim_secs: time_until,
            claim_amount: self.config.claim_amount,
            total_claimed: claim_info.total_claimed,
        })
    }

    /// Get claim info for an address
    pub async fn get_claim_info(&self, address: &str) -> Result<ClaimInfo> {
        // Check cache first
        {
            let cache = self.claim_cache.read().await;
            if let Some(info) = cache.get(address) {
                return Ok(info.clone());
            }
        }

        // Query from chain
        let info = self.query_claim_info_from_chain(address).await?;

        // Update cache
        {
            let mut cache = self.claim_cache.write().await;
            cache.insert(address.to_string(), info.clone());
        }

        Ok(info)
    }

    /// Claim tokens from faucet
    pub async fn claim(&self, address: &str, ip_address: Option<&str>) -> Result<ClaimResult> {
        if !self.config.enabled {
            return Err(anyhow!("Faucet is disabled"));
        }

        // Check rate limit by IP
        if let Some(ip) = ip_address {
            self.check_rate_limit(ip).await?;
        }

        // Check if can claim
        let status = self.get_status(address).await?;
        if !status.can_claim {
            return Err(anyhow!(
                "Cannot claim yet. Please wait {} seconds.",
                status.time_until_next_claim_secs
            ));
        }

        info!("Processing faucet claim for address: {}", address);

        // Parse address
        let recipient = FieldElement::from_hex_be(address)
            .map_err(|e| anyhow!("Invalid address format: {}", e))?;

        // Build claim transaction
        let claim_amount_felt = FieldElement::from(self.config.claim_amount);

        // Call faucet contract's claim function
        // Selector: claim(recipient: ContractAddress)
        let selector = starknet::core::utils::get_selector_from_name("claim")
            .map_err(|e| anyhow!("Failed to get selector: {}", e))?;

        let calldata = vec![recipient];

        // For now, return a mock result since we don't have signing credentials here
        // In production, this would be signed by the faucet's account
        let tx_hash = self.execute_claim(recipient, claim_amount_felt).await?;

        // Update local cache
        {
            let mut cache = self.claim_cache.write().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let entry = cache.entry(address.to_string()).or_insert(ClaimInfo {
                last_claim_at: None,
                total_claimed: 0,
                claim_count: 0,
            });

            entry.last_claim_at = Some(now);
            entry.total_claimed += self.config.claim_amount;
            entry.claim_count += 1;
        }

        // Update rate limit
        if let Some(ip) = ip_address {
            self.update_rate_limit(ip).await;
        }

        info!("Faucet claim successful for {}: {} SAGE", address, self.config.claim_amount);

        Ok(ClaimResult {
            success: true,
            amount: self.config.claim_amount,
            transaction_hash: tx_hash,
            new_balance: None, // Would query from chain
        })
    }

    /// Check rate limit for IP address
    async fn check_rate_limit(&self, ip: &str) -> Result<()> {
        let limits = self.rate_limits.read().await;

        if let Some(entry) = limits.get(ip) {
            // Max 3 requests per hour
            if entry.request_count >= 3 && entry.last_request.elapsed() < Duration::from_secs(3600) {
                return Err(anyhow!(
                    "Rate limit exceeded. Please try again in {} minutes.",
                    (3600 - entry.last_request.elapsed().as_secs()) / 60
                ));
            }
        }

        Ok(())
    }

    /// Update rate limit for IP
    async fn update_rate_limit(&self, ip: &str) {
        let mut limits = self.rate_limits.write().await;

        let entry = limits.entry(ip.to_string()).or_insert(RateLimitEntry {
            last_request: Instant::now(),
            request_count: 0,
        });

        // Reset if more than an hour has passed
        if entry.last_request.elapsed() > Duration::from_secs(3600) {
            entry.request_count = 0;
        }

        entry.last_request = Instant::now();
        entry.request_count += 1;
    }

    /// Query claim info from chain
    async fn query_claim_info_from_chain(&self, address: &str) -> Result<ClaimInfo> {
        // In production, this would call the faucet contract's get_claim_info function
        // For now, return default (never claimed)
        debug!("Querying claim info for {} from chain", address);

        Ok(ClaimInfo {
            last_claim_at: None,
            total_claimed: 0,
            claim_count: 0,
        })
    }

    /// Execute the claim transaction
    async fn execute_claim(
        &self,
        recipient: FieldElement,
        amount: FieldElement,
    ) -> Result<FieldElement> {
        // In production, this would:
        // 1. Build the transaction
        // 2. Sign with faucet's private key
        // 3. Submit to network
        // 4. Return transaction hash

        // For now, return a mock transaction hash
        // The actual implementation would use the coordinator's credentials
        debug!(
            "Executing claim: recipient={:#x}, amount={:#x}",
            recipient, amount
        );

        // Generate a pseudo-random tx hash for demo purposes
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let tx_hash = FieldElement::from(now as u64);

        Ok(tx_hash)
    }

    /// Clean up old rate limit entries
    pub async fn cleanup_rate_limits(&self) {
        let mut limits = self.rate_limits.write().await;
        let now = Instant::now();

        limits.retain(|_, entry| {
            now.duration_since(entry.last_request) < Duration::from_secs(3600)
        });
    }

    /// Refresh claim cache for an address
    pub async fn refresh_cache(&self, address: &str) -> Result<()> {
        let info = self.query_claim_info_from_chain(address).await?;

        let mut cache = self.claim_cache.write().await;
        cache.insert(address.to_string(), info);

        Ok(())
    }
}

/// Faucet configuration (public)
#[derive(Debug, Clone, serde::Serialize)]
pub struct FaucetConfig {
    pub claim_amount: u64,
    pub cooldown_secs: u64,
    pub enabled: bool,
}
