use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use crate::security::tee::{TEEContext, AttestationQuote};
use futures::StreamExt;
use tokio::io::AsyncWriteExt;

pub struct SecureGateway {
    tee_context: TEEContext,
}

impl SecureGateway {
    pub fn new() -> Self {
        Self {
            tee_context: TEEContext::new(),
        }
    }

    /// Fetch data from a URL, streaming it to a temporary file while calculating its hash
    /// Returns the path to the file and the TEE attestation
    pub async fn fetch_and_encrypt_stream(&self, url: &str) -> Result<(String, AttestationQuote)> {
        // 1. Start the fetch
        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch data: status {}", response.status()));
        }

        // 2. Setup streaming and hashing
        let mut stream = response.bytes_stream();
        let mut hasher = Sha256::new();
        
        // Create a temporary file for the data
        let temp_path = format!("/tmp/bitsage_ingest_{}.tmp", uuid::Uuid::new_v4());
        let mut file = tokio::fs::File::create(&temp_path).await?;

        // 3. Stream processing loop
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            // Update hash
            hasher.update(&chunk);
            // Write to disk
            file.write_all(&chunk).await?;
        }
        file.flush().await?;

        let final_hash = hasher.finalize();

        // 4. Generate TEE Quote over the hash
        let quote = self.tee_context.generate_quote(&final_hash)?;

        Ok((temp_path, quote))
    }
}

