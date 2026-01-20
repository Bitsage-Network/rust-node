// Worker-Contract Bridge
// Connects Rust workers to Starknet smart contracts

use anyhow::Result;
use starknet::{
    core::types::{FieldElement, FunctionCall},
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount, Call},
    providers::{jsonrpc::HttpTransport, JsonRpcClient},
    signers::{LocalWallet, SigningKey},
};
use starknet::core::utils::get_selector_from_name;
use std::sync::Arc;

use crate::obelysk::{TEEQuote, Matrix, ObelyskVM};
use crate::types::JobId;

/// Bridge between Rust worker and Starknet contracts
pub struct WorkerBridge {
    /// Starknet account for signing transactions
    account: Arc<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>>,

    /// Provider for read-only calls
    provider: Arc<JsonRpcClient<HttpTransport>>,

    /// OptimisticTEE contract address
    optimistic_tee_address: FieldElement,

    /// Worker ID (felt252)
    worker_id: FieldElement,
}

impl WorkerBridge {
    /// Create a new worker bridge
    pub fn new(
        rpc_url: &str,
        private_key: &str,
        account_address: FieldElement,
        chain_id: FieldElement,
        optimistic_tee_address: FieldElement,
        worker_id: FieldElement,
    ) -> Result<Self> {
        // Setup provider
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(rpc_url)?,
        )));

        // Setup signer
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(
            FieldElement::from_hex_be(private_key)?,
        ));

        // Create account with cloned provider
        let account = Arc::new(SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address,
            chain_id,
            ExecutionEncoding::New,
        ));

        Ok(Self {
            account,
            provider,
            optimistic_tee_address,
            worker_id,
        })
    }

    /// Submit a job result to the OptimisticTEE contract
    pub async fn submit_result(
        &self,
        job_id: &JobId,
        result_hash: FieldElement,
        tee_quote: &TEEQuote,
    ) -> Result<FieldElement> {
        // Convert job_id to u256 (low, high)
        let job_id_str = job_id.0.to_string();
        let job_id_low = FieldElement::from_dec_str(&job_id_str)?;
        let job_id_high = FieldElement::ZERO;

        // Extract enclave measurement from quote
        let enclave_measurement = if tee_quote.mrenclave.len() >= 32 {
            FieldElement::from_bytes_be(&tee_quote.mrenclave[0..32].try_into()?)?
        } else {
            FieldElement::ZERO
        };

        // Convert signature to Array<felt252>
        let signature_felts: Vec<FieldElement> = tee_quote.signature
            .chunks(31) // felt252 can hold 31 bytes
            .map(|chunk| FieldElement::from_byte_slice_be(chunk).unwrap_or(FieldElement::ZERO))
            .collect();

        // Build calldata
        let mut calldata = vec![
            job_id_low,
            job_id_high,
            self.worker_id,
            result_hash,
            enclave_measurement,
            FieldElement::from(signature_felts.len() as u64), // Array length
        ];
        calldata.extend(signature_felts);

        // Execute transaction
        let call = Call {
            to: self.optimistic_tee_address,
            selector: get_selector_from_name("submit_result")?,
            calldata,
        };

        let result = self.account
            .execute(vec![call])
            .send()
            .await?;

        Ok(result.transaction_hash)
    }

    /// Check if a job result has been finalized on-chain
    pub async fn is_result_finalized(&self, job_id: &JobId) -> Result<bool> {
        use starknet::providers::Provider;
        use starknet::core::types::BlockId;

        let job_id_str = job_id.0.to_string();
        let job_id_low = FieldElement::from_dec_str(&job_id_str)?;
        let job_id_high = FieldElement::ZERO;

        let call = FunctionCall {
            contract_address: self.optimistic_tee_address,
            entry_point_selector: get_selector_from_name("get_result_status")?,
            calldata: vec![job_id_low, job_id_high],
        };

        // Use provider to make the read-only call
        let result = self.provider
            .call(call, BlockId::Tag(starknet::core::types::BlockTag::Latest))
            .await;

        match result {
            Ok(values) => {
                // Result status: 0 = pending, 1 = submitted, 2 = challenged, 3 = finalized
                // A result is finalized when status == 3
                if let Some(status) = values.first() {
                    Ok(*status == FieldElement::from(3u8))
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                // If contract call fails (e.g., job doesn't exist), return false
                tracing::debug!("Failed to query result status for job {}: {}", job_id, e);
                Ok(false)
            }
        }
    }

    /// Fetch available jobs from on-chain (decentralized job discovery)
    pub async fn poll_pending_jobs(&self, job_manager_address: FieldElement, limit: u64) -> Result<Vec<OnChainJob>> {
        use starknet::providers::Provider;
        use starknet::core::types::BlockId;

        let call = FunctionCall {
            contract_address: job_manager_address,
            entry_point_selector: get_selector_from_name("get_pending_jobs")?,
            calldata: vec![
                FieldElement::ZERO,  // offset
                FieldElement::from(limit),  // limit
            ],
        };

        let result = self.provider
            .call(call, BlockId::Tag(starknet::core::types::BlockTag::Latest))
            .await;

        match result {
            Ok(values) => {
                // Parse array of JobId values
                // First element is array length
                let mut jobs = Vec::new();
                if values.is_empty() {
                    return Ok(jobs);
                }

                let len = values[0].to_string().parse::<usize>().unwrap_or(0);
                for i in 0..len {
                    if i + 1 < values.len() {
                        // Each JobId is a u256 (low, high)
                        let job_id_low = values[1 + i * 2];
                        let _job_id_high = if 2 + i * 2 < values.len() {
                            values[2 + i * 2]
                        } else {
                            FieldElement::ZERO
                        };

                        jobs.push(OnChainJob {
                            job_id: JobId(uuid::Uuid::new_v4()), // Temporary - need proper conversion
                            job_type: 0, // Will be fetched with job details
                            input_hash: job_id_low,
                            assigned_worker: FieldElement::ZERO,
                            job_id_felt: job_id_low,
                        });
                    }
                }
                Ok(jobs)
            }
            Err(e) => {
                tracing::debug!("Failed to fetch pending jobs: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Claim a job on-chain (decentralized - worker claims directly)
    pub async fn claim_job(&self, job_manager_address: FieldElement, job_id_low: FieldElement, job_id_high: FieldElement) -> Result<FieldElement> {
        let call = Call {
            to: job_manager_address,
            selector: get_selector_from_name("claim_job")?,
            calldata: vec![job_id_low, job_id_high],
        };

        let result = self.account
            .execute(vec![call])
            .send()
            .await?;

        Ok(result.transaction_hash)
    }

    /// Get pending job count
    pub async fn get_pending_job_count(&self, job_manager_address: FieldElement) -> Result<u64> {
        use starknet::providers::Provider;
        use starknet::core::types::BlockId;

        let call = FunctionCall {
            contract_address: job_manager_address,
            entry_point_selector: get_selector_from_name("get_pending_job_count")?,
            calldata: vec![],
        };

        let result = self.provider
            .call(call, BlockId::Tag(starknet::core::types::BlockTag::Latest))
            .await?;

        if let Some(count) = result.first() {
            Ok(count.to_string().parse::<u64>().unwrap_or(0))
        } else {
            Ok(0)
        }
    }
}

/// Job fetched from on-chain
#[derive(Debug, Clone)]
pub struct OnChainJob {
    pub job_id: JobId,
    pub job_type: u8,
    pub input_hash: FieldElement,
    pub assigned_worker: FieldElement,
    pub job_id_felt: FieldElement,
}

/// Helper to convert OVM execution result to hash
pub fn hash_execution_result(vm: &ObelyskVM, output_regs: &[usize]) -> FieldElement {
    use sha3::{Digest, Keccak256};
    
    let mut hasher = Keccak256::new();
    
    // Hash the output register values
    for &reg_idx in output_regs {
        let val = vm.registers()[reg_idx].value();
        hasher.update(val.to_be_bytes());
    }
    
    let hash_bytes = hasher.finalize();
    FieldElement::from_bytes_be(&hash_bytes.into()).unwrap_or(FieldElement::ZERO)
}

/// Helper to convert Matrix result to hash
pub fn hash_matrix_result(matrix: &Matrix) -> FieldElement {
    use sha3::{Digest, Keccak256};
    
    let mut hasher = Keccak256::new();
    
    // Hash dimensions
    hasher.update((matrix.rows as u64).to_be_bytes());
    hasher.update((matrix.cols as u64).to_be_bytes());
    
    // Hash all elements
    for elem in &matrix.data {
        hasher.update(elem.value().to_be_bytes());
    }
    
    let hash_bytes = hasher.finalize();
    FieldElement::from_bytes_be(&hash_bytes.into()).unwrap_or(FieldElement::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::M31;

    #[test]
    fn test_hash_consistency() {
        let mat1 = Matrix::from_data(2, 2, vec![
            M31::new(1), M31::new(2),
            M31::new(3), M31::new(4),
        ]).unwrap();
        
        let hash1 = hash_matrix_result(&mat1);
        let hash2 = hash_matrix_result(&mat1);
        
        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }
}

