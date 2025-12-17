// Payment Router Client for Obelysk
//
// Rust client for interacting with the Cairo PaymentRouter contract.
// Handles multi-token payments, quotes, and privacy credit management.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use starknet::{
    core::types::{FieldElement, FunctionCall, BlockId, BlockTag},
    core::utils::get_selector_from_name,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount, Call},
    signers::{LocalWallet, SigningKey},
};
use std::sync::Arc;
use tracing::{info, debug};

use super::privacy_client::{felt252_to_field_element, field_element_to_felt252};

// =============================================================================
// Contract Types (mirroring Cairo structs)
// =============================================================================

/// Supported payment tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentToken {
    USDC = 0,
    STRK = 1,
    WBTC = 2,
    SAGE = 3,
    StakedSAGE = 4,
    PrivacyCredit = 5,
}

impl PaymentToken {
    pub fn to_felt(&self) -> FieldElement {
        FieldElement::from(*self as u64)
    }

    pub fn from_felt(fe: &FieldElement) -> Option<Self> {
        let val = felt_to_u64(fe);
        match val {
            0 => Some(PaymentToken::USDC),
            1 => Some(PaymentToken::STRK),
            2 => Some(PaymentToken::WBTC),
            3 => Some(PaymentToken::SAGE),
            4 => Some(PaymentToken::StakedSAGE),
            5 => Some(PaymentToken::PrivacyCredit),
            _ => None,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            PaymentToken::USDC => "USDC",
            PaymentToken::STRK => "STRK",
            PaymentToken::WBTC => "wBTC",
            PaymentToken::SAGE => "SAGE",
            PaymentToken::StakedSAGE => "Staked SAGE",
            PaymentToken::PrivacyCredit => "Privacy Credit",
        }
    }

    /// Get discount description
    pub fn discount_description(&self) -> &'static str {
        match self {
            PaymentToken::USDC | PaymentToken::STRK | PaymentToken::WBTC => "0% (standard)",
            PaymentToken::SAGE => "5% off",
            PaymentToken::StakedSAGE => "10% off (best)",
            PaymentToken::PrivacyCredit => "2% off",
        }
    }
}

/// Payment quote from OTC desk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentQuote {
    pub quote_id: u128,
    pub payment_token: PaymentToken,
    pub payment_amount: u128,
    pub sage_equivalent: u128,
    pub discount_bps: u32,
    pub usd_value: u128,
    pub expires_at: u64,
    pub is_valid: bool,
}

/// Fee distribution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    pub worker_bps: u32,
    pub protocol_fee_bps: u32,
    pub burn_share_bps: u32,
    pub treasury_share_bps: u32,
    pub staker_share_bps: u32,
}

/// Discount tiers by payment method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscountTiers {
    pub stablecoin_discount_bps: u32,
    pub strk_discount_bps: u32,
    pub wbtc_discount_bps: u32,
    pub sage_discount_bps: u32,
    pub staked_sage_discount_bps: u32,
    pub privacy_credit_discount_bps: u32,
}

/// OTC desk configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTCConfig {
    pub usdc_address: FieldElement,
    pub strk_address: FieldElement,
    pub wbtc_address: FieldElement,
    pub sage_address: FieldElement,
    pub oracle_address: FieldElement,
    pub staking_address: FieldElement,
    pub quote_validity_seconds: u64,
    pub max_slippage_bps: u32,
}

// =============================================================================
// Payment Router Client
// =============================================================================

/// Client for interacting with the PaymentRouter contract
pub struct PaymentRouterClient {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    contract_address: FieldElement,
    account: Option<Arc<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>>>,
}

impl PaymentRouterClient {
    /// Create a new client with read-only access
    pub fn new_readonly(rpc_url: &str, contract_address: FieldElement) -> Result<Self> {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?
        )));

        Ok(Self {
            provider,
            contract_address,
            account: None,
        })
    }

    /// Create a new client with write access
    pub async fn new(
        rpc_url: &str,
        contract_address: FieldElement,
        private_key: &str,
        account_address: FieldElement,
    ) -> Result<Self> {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(rpc_url).map_err(|e| anyhow!("Invalid RPC URL: {}", e))?
        )));

        let signer = LocalWallet::from(
            SigningKey::from_secret_scalar(
                FieldElement::from_hex_be(private_key)
                    .map_err(|e| anyhow!("Invalid private key: {}", e))?
            )
        );

        let chain_id = provider.chain_id().await?;

        let account = Arc::new(SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address,
            chain_id,
            ExecutionEncoding::New,
        ));

        Ok(Self {
            provider,
            contract_address,
            account: Some(account),
        })
    }

    // =========================================================================
    // Read Methods
    // =========================================================================

    /// Get a payment quote for compute services
    pub async fn get_quote(
        &self,
        payment_token: PaymentToken,
        usd_amount: u128,
    ) -> Result<PaymentQuote> {
        let usd_low = FieldElement::from(usd_amount as u64);
        let usd_high = FieldElement::from((usd_amount >> 64) as u64);

        let calldata = vec![payment_token.to_felt(), usd_low, usd_high];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_quote")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_quote(&result)
    }

    /// Get current discount tiers
    pub async fn get_discount_tiers(&self) -> Result<DiscountTiers> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_discount_tiers")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_discount_tiers(&result)
    }

    /// Get fee distribution configuration
    pub async fn get_fee_distribution(&self) -> Result<FeeDistribution> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_fee_distribution")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_fee_distribution(&result)
    }

    /// Get OTC desk configuration
    pub async fn get_otc_config(&self) -> Result<OTCConfig> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_otc_config")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_otc_config(&result)
    }

    // =========================================================================
    // Write Methods
    // =========================================================================

    /// Execute payment using a quote
    pub async fn execute_payment(
        &self,
        quote_id: u128,
        job_id: u128,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(quote_id as u64),
            FieldElement::from((quote_id >> 64) as u64),
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        info!("Executing payment for job {} with quote {}", job_id, quote_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("execute_payment")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Execute payment tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Pay directly with SAGE tokens (no quote needed, 5% discount)
    pub async fn pay_with_sage(
        &self,
        amount: u128,
        job_id: u128,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(amount as u64),
            FieldElement::from((amount >> 64) as u64),
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        info!("Paying {} SAGE for job {} (5% discount)", amount, job_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("pay_with_sage")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Pay with SAGE tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Pay using staked SAGE position (10% discount)
    pub async fn pay_with_staked_sage(
        &self,
        usd_amount: u128,
        job_id: u128,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(usd_amount as u64),
            FieldElement::from((usd_amount >> 64) as u64),
            FieldElement::from(job_id as u64),
            FieldElement::from((job_id >> 64) as u64),
        ];

        info!("Paying with staked SAGE for job {} (10% discount)", job_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("pay_with_staked_sage")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Pay with staked SAGE tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Deposit privacy credits
    pub async fn deposit_privacy_credits(
        &self,
        amount: u128,
        commitment: FieldElement,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let calldata = vec![
            FieldElement::from(amount as u64),
            FieldElement::from((amount >> 64) as u64),
            commitment,
        ];

        info!("Depositing {} SAGE as privacy credits", amount);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("deposit_privacy_credits")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Deposit privacy credits tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Pay using privacy credits (2% discount)
    pub async fn pay_with_privacy_credits(
        &self,
        usd_amount: u128,
        nullifier: FieldElement,
        proof: Vec<FieldElement>,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let mut calldata = vec![
            FieldElement::from(usd_amount as u64),
            FieldElement::from((usd_amount >> 64) as u64),
            nullifier,
            FieldElement::from(proof.len() as u64),
        ];
        calldata.extend(proof);

        info!("Paying with privacy credits (2% discount)");

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("pay_with_privacy_credits")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Pay with privacy credits tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    // =========================================================================
    // Parsing Helpers
    // =========================================================================

    fn parse_quote(data: &[FieldElement]) -> Result<PaymentQuote> {
        if data.len() < 10 {
            return Err(anyhow!("Insufficient data for PaymentQuote"));
        }

        let quote_id = felt_to_u64(&data[0]) as u128 | ((felt_to_u64(&data[1]) as u128) << 64);
        let payment_token = PaymentToken::from_felt(&data[2])
            .ok_or_else(|| anyhow!("Invalid payment token"))?;
        let payment_amount = felt_to_u64(&data[3]) as u128 | ((felt_to_u64(&data[4]) as u128) << 64);
        let sage_equivalent = felt_to_u64(&data[5]) as u128 | ((felt_to_u64(&data[6]) as u128) << 64);
        let discount_bps = felt_to_u64(&data[7]) as u32;
        let usd_value = felt_to_u64(&data[8]) as u128 | ((felt_to_u64(&data[9]) as u128) << 64);
        let expires_at = data.get(10).map(felt_to_u64).unwrap_or(0);
        let is_valid = data.get(11).map(|f| *f != FieldElement::ZERO).unwrap_or(false);

        Ok(PaymentQuote {
            quote_id,
            payment_token,
            payment_amount,
            sage_equivalent,
            discount_bps,
            usd_value,
            expires_at,
            is_valid,
        })
    }

    fn parse_discount_tiers(data: &[FieldElement]) -> Result<DiscountTiers> {
        if data.len() < 6 {
            return Err(anyhow!("Insufficient data for DiscountTiers"));
        }

        Ok(DiscountTiers {
            stablecoin_discount_bps: felt_to_u64(&data[0]) as u32,
            strk_discount_bps: felt_to_u64(&data[1]) as u32,
            wbtc_discount_bps: felt_to_u64(&data[2]) as u32,
            sage_discount_bps: felt_to_u64(&data[3]) as u32,
            staked_sage_discount_bps: felt_to_u64(&data[4]) as u32,
            privacy_credit_discount_bps: felt_to_u64(&data[5]) as u32,
        })
    }

    fn parse_fee_distribution(data: &[FieldElement]) -> Result<FeeDistribution> {
        if data.len() < 5 {
            return Err(anyhow!("Insufficient data for FeeDistribution"));
        }

        Ok(FeeDistribution {
            worker_bps: felt_to_u64(&data[0]) as u32,
            protocol_fee_bps: felt_to_u64(&data[1]) as u32,
            burn_share_bps: felt_to_u64(&data[2]) as u32,
            treasury_share_bps: felt_to_u64(&data[3]) as u32,
            staker_share_bps: felt_to_u64(&data[4]) as u32,
        })
    }

    fn parse_otc_config(data: &[FieldElement]) -> Result<OTCConfig> {
        if data.len() < 8 {
            return Err(anyhow!("Insufficient data for OTCConfig"));
        }

        Ok(OTCConfig {
            usdc_address: data[0],
            strk_address: data[1],
            wbtc_address: data[2],
            sage_address: data[3],
            oracle_address: data[4],
            staking_address: data[5],
            quote_validity_seconds: felt_to_u64(&data[6]),
            max_slippage_bps: felt_to_u64(&data[7]) as u32,
        })
    }
}

// =============================================================================
// Payment Calculator
// =============================================================================

/// Helper to calculate optimal payment method
pub struct PaymentCalculator;

impl PaymentCalculator {
    /// Calculate the best payment method for a given USD amount
    pub fn recommend_payment_method(
        usd_amount: u128,
        has_staked_sage: bool,
        has_sage_balance: u128,
        sage_price_usd: u128,
    ) -> (PaymentToken, String) {
        if has_staked_sage {
            return (PaymentToken::StakedSAGE,
                "Staked SAGE (10% discount - best value)".to_string());
        }

        let sage_needed = if sage_price_usd > 0 {
            (usd_amount * 10u128.pow(18)) / sage_price_usd
        } else {
            0
        };
        let sage_with_discount = (sage_needed * 95) / 100;

        if has_sage_balance >= sage_with_discount && sage_with_discount > 0 {
            return (PaymentToken::SAGE,
                format!("SAGE direct (5% discount, {} SAGE needed)", sage_with_discount));
        }

        (PaymentToken::USDC, "USDC (no discount)".to_string())
    }

    /// Calculate effective cost after discount
    pub fn calculate_effective_cost(usd_amount: u128, discount_bps: u32) -> u128 {
        let discount_factor = 10000 - discount_bps as u128;
        (usd_amount * discount_factor) / 10000
    }

    /// Calculate worker payment from total
    pub fn calculate_worker_share(total_payment: u128, fee_distribution: &FeeDistribution) -> u128 {
        (total_payment * fee_distribution.worker_bps as u128) / 10000
    }

    /// Calculate protocol fee breakdown
    pub fn calculate_protocol_breakdown(
        total_payment: u128,
        fee_distribution: &FeeDistribution,
    ) -> (u128, u128, u128) {
        let protocol_fee = (total_payment * fee_distribution.protocol_fee_bps as u128) / 10000;
        let burn = (protocol_fee * fee_distribution.burn_share_bps as u128) / 10000;
        let treasury = (protocol_fee * fee_distribution.treasury_share_bps as u128) / 10000;
        let stakers = (protocol_fee * fee_distribution.staker_share_bps as u128) / 10000;
        (burn, treasury, stakers)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn felt_to_u64(fe: &FieldElement) -> u64 {
    let bytes = fe.to_bytes_be();
    u64::from_be_bytes(bytes[24..32].try_into().unwrap_or([0; 8]))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_token_conversion() {
        for token in [
            PaymentToken::USDC,
            PaymentToken::STRK,
            PaymentToken::WBTC,
            PaymentToken::SAGE,
            PaymentToken::StakedSAGE,
            PaymentToken::PrivacyCredit,
        ] {
            let felt = token.to_felt();
            let back = PaymentToken::from_felt(&felt).unwrap();
            assert_eq!(token, back);
        }
    }

    #[test]
    fn test_calculate_effective_cost() {
        let cost = PaymentCalculator::calculate_effective_cost(1000_000000000000000000, 500);
        assert_eq!(cost, 950_000000000000000000);
    }

    #[test]
    fn test_calculate_worker_share() {
        let fee_dist = FeeDistribution {
            worker_bps: 8000,
            protocol_fee_bps: 2000,
            burn_share_bps: 7000,
            treasury_share_bps: 2000,
            staker_share_bps: 1000,
        };

        let worker_share = PaymentCalculator::calculate_worker_share(100_000000000000000000, &fee_dist);
        assert_eq!(worker_share, 80_000000000000000000);
    }

    #[test]
    fn test_protocol_breakdown() {
        let fee_dist = FeeDistribution {
            worker_bps: 8000,
            protocol_fee_bps: 2000,
            burn_share_bps: 7000,
            treasury_share_bps: 2000,
            staker_share_bps: 1000,
        };

        let (burn, treasury, stakers) =
            PaymentCalculator::calculate_protocol_breakdown(100_000000000000000000, &fee_dist);

        assert_eq!(burn, 14_000000000000000000);
        assert_eq!(treasury, 4_000000000000000000);
        assert_eq!(stakers, 2_000000000000000000);
    }

    #[test]
    fn test_recommend_payment() {
        let (token, _) = PaymentCalculator::recommend_payment_method(
            1000_000000000000000000,
            true,
            0,
            1_000000000000000000,
        );
        assert_eq!(token, PaymentToken::StakedSAGE);

        let (token, _) = PaymentCalculator::recommend_payment_method(
            100_000000000000000000,
            false,
            200_000000000000000000,
            1_000000000000000000,
        );
        assert_eq!(token, PaymentToken::SAGE);

        let (token, _) = PaymentCalculator::recommend_payment_method(
            100_000000000000000000,
            false,
            0,
            1_000000000000000000,
        );
        assert_eq!(token, PaymentToken::USDC);
    }
}
