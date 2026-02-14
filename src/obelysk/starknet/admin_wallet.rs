//! Starknet Admin Wallet for Faucet Token Distribution
//!
//! Simple wrapper around SingleOwnerAccount for sending SAGE tokens
//! from the faucet admin wallet to users who complete social tasks.

use anyhow::{Context, Result};
use starknet::{
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount},
    core::types::FieldElement,
    providers::{jsonrpc::HttpTransport, JsonRpcClient},
    signers::{LocalWallet, SigningKey},
};
use tracing::{info, error};

/// Admin wallet for distributing SAGE tokens
pub struct StarknetAdminWallet {
    account: SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    sage_token_address: FieldElement,
}

impl StarknetAdminWallet {
    /// Create a new admin wallet from environment config
    pub fn new(
        rpc_url: &str,
        admin_address: &str,
        admin_private_key: &str,
        sage_token_address: &str,
        chain_id: FieldElement,
    ) -> Result<Self> {
        let address = FieldElement::from_hex_be(admin_address)
            .context("Invalid admin address")?;
        let private_key = FieldElement::from_hex_be(admin_private_key)
            .context("Invalid admin private key")?;
        let sage_token = FieldElement::from_hex_be(sage_token_address)
            .context("Invalid SAGE token address")?;

        let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
        let provider = JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(rpc_url).context("Invalid RPC URL")?,
        ));

        let account = SingleOwnerAccount::new(
            provider,
            signer,
            address,
            chain_id,
            ExecutionEncoding::New,
        );

        info!("Admin wallet initialized for address: {:#066x}", address);

        Ok(Self {
            account,
            sage_token_address: sage_token,
        })
    }

    /// Transfer SAGE tokens to a recipient
    ///
    /// Calls the SAGE token contract's `transfer(recipient, amount_u256)` function.
    /// Returns the transaction hash on success.
    pub async fn transfer_sage(
        &self,
        recipient: &str,
        amount: u128,
    ) -> Result<String> {
        let recipient_felt = FieldElement::from_hex_be(recipient)
            .context("Invalid recipient address")?;

        // ERC-20 transfer selector: sn_keccak("transfer")
        let transfer_selector = starknet::core::utils::get_selector_from_name("transfer")
            .context("Failed to compute transfer selector")?;

        // Amount as Uint256 (low, high) — social rewards are small so high = 0
        let amount_low = FieldElement::from(amount);
        let amount_high = FieldElement::ZERO;

        let call = starknet::accounts::Call {
            to: self.sage_token_address,
            selector: transfer_selector,
            calldata: vec![recipient_felt, amount_low, amount_high],
        };

        let execution = self.account.execute(vec![call]);
        let result = execution
            .send()
            .await
            .context("Failed to send SAGE transfer transaction")?;

        let tx_hash = format!("{:#066x}", result.transaction_hash);
        info!(
            "SAGE transfer sent: {} wei to {} (tx: {})",
            amount, recipient, tx_hash
        );

        Ok(tx_hash)
    }
}
