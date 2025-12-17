// Privacy Router Client for Obelysk
//
// Rust client for interacting with the Cairo PrivacyRouter contract.
// Handles encrypted balance management and private worker payments.

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

use super::elgamal::{
    Felt252, ECPoint, ElGamalCiphertext, EncryptionProof, EncryptedBalance, KeyPair,
    decrypt_point, create_decryption_proof, hash_felts, encrypt,
};

// =============================================================================
// Contract Types (mirroring Cairo structs)
// =============================================================================

/// Private account state from the contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAccount {
    pub public_key: ECPoint,
    pub encrypted_balance: EncryptedBalance,
    pub pending_transfers: u32,
    pub last_rollup_epoch: u64,
    pub is_registered: bool,
}

/// Private worker payment info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateWorkerPayment {
    pub job_id: u128,
    pub worker: FieldElement,
    pub encrypted_amount: ElGamalCiphertext,
    pub timestamp: u64,
    pub is_claimed: bool,
}

/// Transfer proof for private transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProof {
    pub sender_proof: EncryptionProof,
    pub receiver_proof: EncryptionProof,
    pub balance_proof: EncryptionProof,
}

// =============================================================================
// Privacy Router Client
// =============================================================================

/// Client for interacting with the PrivacyRouter contract
pub struct PrivacyRouterClient {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    contract_address: FieldElement,
    account: Option<Arc<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>>>,
}

impl PrivacyRouterClient {
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

    /// Create a new client with write access (requires account)
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

    /// Get account info from the contract
    pub async fn get_account(&self, address: FieldElement) -> Result<PrivateAccount> {
        let calldata = vec![address];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_account")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_private_account(&result)
    }

    /// Get worker payment info
    pub async fn get_worker_payment(&self, job_id: u128) -> Result<PrivateWorkerPayment> {
        let job_id_low = FieldElement::from(job_id as u64);
        let job_id_high = FieldElement::from((job_id >> 64) as u64);

        let calldata = vec![job_id_low, job_id_high];

        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_worker_payment")?,
                calldata,
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Self::parse_worker_payment(&result)
    }

    /// Check if a nullifier has been used
    pub async fn is_nullifier_used(&self, nullifier: FieldElement) -> Result<bool> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("is_nullifier_used")?,
                calldata: vec![nullifier],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        Ok(result.first().map(|f| *f != FieldElement::ZERO).unwrap_or(false))
    }

    /// Get current epoch
    pub async fn get_current_epoch(&self) -> Result<u64> {
        let result = self.provider.call(
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: get_selector_from_name("get_current_epoch")?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        ).await?;

        result.first()
            .map(|f| felt_to_u64(f))
            .ok_or_else(|| anyhow!("Empty response"))
    }

    // =========================================================================
    // Write Methods (require account)
    // =========================================================================

    /// Register a new private account with the worker's ElGamal public key
    pub async fn register_account(&self, keypair: &KeyPair) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let public_key = keypair.public_key();
        let calldata = vec![
            felt252_to_field_element(&public_key.x),
            felt252_to_field_element(&public_key.y),
        ];

        info!("Registering privacy account with public key: ({}, {})",
              public_key.x.to_hex(), public_key.y.to_hex());

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("register_account")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Register account tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Deposit SAGE tokens into private account
    pub async fn deposit(
        &self,
        keypair: &KeyPair,
        amount: u64,
        randomness: &Felt252,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Encrypt the amount
        let encrypted_amount = encrypt(amount, &keypair.public_key, randomness);

        // Create encryption proof
        let proof = create_encryption_proof(keypair, &encrypted_amount, randomness)?;

        let calldata = build_deposit_calldata(amount, &encrypted_amount, &proof);

        info!("Depositing {} tokens with privacy", amount);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("deposit")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Deposit tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Claim a private worker payment
    pub async fn claim_worker_payment(
        &self,
        keypair: &KeyPair,
        job_id: u128,
        nonce: &Felt252,
    ) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        // Get the payment info
        let payment = self.get_worker_payment(job_id).await?;

        if payment.is_claimed {
            return Err(anyhow!("Payment already claimed"));
        }

        // Create decryption proof
        let proof = create_decryption_proof(keypair, &payment.encrypted_amount, nonce);

        let job_id_low = FieldElement::from(job_id as u64);
        let job_id_high = FieldElement::from((job_id >> 64) as u64);

        let mut calldata = vec![job_id_low, job_id_high];
        calldata.extend(proof_to_calldata(&proof));

        info!("Claiming worker payment for job {}", job_id);

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("claim_worker_payment")?,
            calldata,
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Claim payment tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    /// Roll up pending balances
    pub async fn rollup_balance(&self) -> Result<FieldElement> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow!("No account configured for write operations"))?;

        let call = Call {
            to: self.contract_address,
            selector: get_selector_from_name("rollup_balance")?,
            calldata: vec![],
        };

        let tx = account.execute(vec![call]).send().await?;

        debug!("Rollup balance tx: {:?}", tx.transaction_hash);
        Ok(tx.transaction_hash)
    }

    // =========================================================================
    // Worker Payment Helpers
    // =========================================================================

    /// Decrypt worker payment amount (off-chain)
    pub fn decrypt_payment(
        &self,
        keypair: &KeyPair,
        encrypted_amount: &ElGamalCiphertext,
    ) -> ECPoint {
        decrypt_point(encrypted_amount, &keypair.secret_key)
    }

    /// Check if worker has pending unclaimed payments
    pub async fn has_unclaimed_payments(
        &self,
        worker_address: FieldElement,
    ) -> Result<bool> {
        let account = self.get_account(worker_address).await?;
        Ok(account.pending_transfers > 0)
    }

    // =========================================================================
    // Parsing Helpers
    // =========================================================================

    fn parse_private_account(data: &[FieldElement]) -> Result<PrivateAccount> {
        if data.len() < 18 {
            return Err(anyhow!("Insufficient data for PrivateAccount"));
        }

        let public_key = ECPoint::new(
            field_element_to_felt252(&data[0]),
            field_element_to_felt252(&data[1]),
        );

        // Parse encrypted balance
        let encrypted_balance = EncryptedBalance {
            ciphertext: ElGamalCiphertext {
                c1_x: field_element_to_felt252(&data[2]),
                c1_y: field_element_to_felt252(&data[3]),
                c2_x: field_element_to_felt252(&data[4]),
                c2_y: field_element_to_felt252(&data[5]),
            },
            pending_in: ElGamalCiphertext {
                c1_x: field_element_to_felt252(&data[6]),
                c1_y: field_element_to_felt252(&data[7]),
                c2_x: field_element_to_felt252(&data[8]),
                c2_y: field_element_to_felt252(&data[9]),
            },
            pending_out: ElGamalCiphertext {
                c1_x: field_element_to_felt252(&data[10]),
                c1_y: field_element_to_felt252(&data[11]),
                c2_x: field_element_to_felt252(&data[12]),
                c2_y: field_element_to_felt252(&data[13]),
            },
            epoch: felt_to_u64(&data[14]),
        };

        let pending_transfers = felt_to_u64(&data[15]) as u32;
        let last_rollup_epoch = felt_to_u64(&data[16]);
        let is_registered = data[17] != FieldElement::ZERO;

        Ok(PrivateAccount {
            public_key,
            encrypted_balance,
            pending_transfers,
            last_rollup_epoch,
            is_registered,
        })
    }

    fn parse_worker_payment(data: &[FieldElement]) -> Result<PrivateWorkerPayment> {
        if data.len() < 9 {
            return Err(anyhow!("Insufficient data for PrivateWorkerPayment"));
        }

        let job_id = felt_to_u64(&data[0]) as u128 | ((felt_to_u64(&data[1]) as u128) << 64);
        let worker = data[2];

        let encrypted_amount = ElGamalCiphertext {
            c1_x: field_element_to_felt252(&data[3]),
            c1_y: field_element_to_felt252(&data[4]),
            c2_x: field_element_to_felt252(&data[5]),
            c2_y: field_element_to_felt252(&data[6]),
        };

        let timestamp = felt_to_u64(&data[7]);
        let is_claimed = data[8] != FieldElement::ZERO;

        Ok(PrivateWorkerPayment {
            job_id,
            worker,
            encrypted_amount,
            timestamp,
            is_claimed,
        })
    }
}

// =============================================================================
// Conversion Helpers
// =============================================================================

/// Convert Felt252 to Starknet FieldElement
pub fn felt252_to_field_element(felt: &Felt252) -> FieldElement {
    FieldElement::from_bytes_be(&felt.to_be_bytes())
        .unwrap_or(FieldElement::ZERO)
}

/// Convert Starknet FieldElement to Felt252
pub fn field_element_to_felt252(fe: &FieldElement) -> Felt252 {
    Felt252::from_be_bytes(&fe.to_bytes_be())
}

/// Convert FieldElement to u64
fn felt_to_u64(fe: &FieldElement) -> u64 {
    let bytes = fe.to_bytes_be();
    u64::from_be_bytes(bytes[24..32].try_into().unwrap_or([0; 8]))
}

/// Create encryption proof for deposit
fn create_encryption_proof(
    keypair: &KeyPair,
    ciphertext: &ElGamalCiphertext,
    randomness: &Felt252,
) -> Result<EncryptionProof> {
    let nonce = hash_felts(&[*randomness, keypair.secret_key]);
    Ok(create_decryption_proof(keypair, ciphertext, &nonce))
}

/// Convert proof to calldata
fn proof_to_calldata(proof: &EncryptionProof) -> Vec<FieldElement> {
    vec![
        felt252_to_field_element(&proof.commitment_x),
        felt252_to_field_element(&proof.commitment_y),
        felt252_to_field_element(&proof.challenge),
        felt252_to_field_element(&proof.response),
        felt252_to_field_element(&proof.range_proof_hash),
    ]
}

/// Build deposit calldata
fn build_deposit_calldata(
    amount: u64,
    encrypted: &ElGamalCiphertext,
    proof: &EncryptionProof,
) -> Vec<FieldElement> {
    let mut calldata = vec![
        FieldElement::from(amount),
        FieldElement::ZERO,
        felt252_to_field_element(&encrypted.c1_x),
        felt252_to_field_element(&encrypted.c1_y),
        felt252_to_field_element(&encrypted.c2_x),
        felt252_to_field_element(&encrypted.c2_y),
    ];
    calldata.extend(proof_to_calldata(proof));
    calldata
}

// =============================================================================
// Worker Privacy Manager
// =============================================================================

/// Manages worker privacy keys and payment claims
pub struct WorkerPrivacyManager {
    keypair: KeyPair,
    client: PrivacyRouterClient,
}

impl WorkerPrivacyManager {
    /// Create a new manager with generated keypair
    pub fn new(client: PrivacyRouterClient, secret: Felt252) -> Self {
        let keypair = KeyPair::from_secret(secret);
        Self { keypair, client }
    }

    /// Get the worker's public key
    pub fn public_key(&self) -> ECPoint {
        self.keypair.public_key()
    }

    /// Register the worker's privacy account
    pub async fn register(&self) -> Result<FieldElement> {
        self.client.register_account(&self.keypair).await
    }

    /// Claim a pending payment
    pub async fn claim_payment(&self, job_id: u128) -> Result<FieldElement> {
        let nonce = hash_felts(&[
            self.keypair.secret_key,
            Felt252::from_u128(job_id),
        ]);

        self.client.claim_worker_payment(&self.keypair, job_id, &nonce).await
    }

    /// Decrypt a received payment (off-chain only)
    pub fn decrypt_payment(&self, encrypted: &ElGamalCiphertext) -> ECPoint {
        self.client.decrypt_payment(&self.keypair, encrypted)
    }

    /// Get current encrypted balance
    pub async fn get_balance(&self, address: FieldElement) -> Result<EncryptedBalance> {
        let account = self.client.get_account(address).await?;
        Ok(account.encrypted_balance)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt_conversion() {
        let original = Felt252::from_u64(12345);
        let fe = felt252_to_field_element(&original);
        let back = field_element_to_felt252(&fe);
        assert_eq!(original, back);
    }

    #[test]
    fn test_proof_to_calldata() {
        let proof = EncryptionProof {
            commitment_x: Felt252::from_u64(1),
            commitment_y: Felt252::from_u64(2),
            challenge: Felt252::from_u64(3),
            response: Felt252::from_u64(4),
            range_proof_hash: Felt252::from_u64(5),
        };

        let calldata = proof_to_calldata(&proof);
        assert_eq!(calldata.len(), 5);
    }
}
