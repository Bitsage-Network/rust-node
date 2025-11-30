use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use std::path::Path;
use std::fs;
use sha2::{Sha256, Digest};

// Linux ConfigFS path for TSM (Trust Security Module) - Standard for TDX/SEV
const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationQuote {
    pub quote_version: u16,
    pub measurement: Vec<u8>, // Extracted from quote body
    pub data_hash: Vec<u8>,   // The REPORT_DATA we submitted
    pub raw_quote: Vec<u8>,   // The full binary quote from hardware
}

pub struct TdxAttestor;

impl TdxAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Generate a real Intel TDX Quote via ConfigFS-TSM
    /// This requires running inside a TDX Guest with configfs mounted
    pub fn generate_quote(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        // 1. Check if TSM is available (Real Hardware Check)
        if !Path::new(TSM_REPORT_PATH).exists() {
             return Err(anyhow!(
                 "TDX/SEV hardware interface not found at {}. Are you running in a Confidential VM?", 
                 TSM_REPORT_PATH
             ));
        }

        // 2. Create a temporary report entry
        let report_name = format!("bitsage_quote_{}", uuid::Uuid::new_v4());
        let report_dir = format!("{}/{}", TSM_REPORT_PATH, report_name);
        
        // mkdir /sys/kernel/config/tsm/report/bitsage_quote_UUID
        fs::create_dir(&report_dir)?;

        // 3. Write REPORT_DATA (User Data) - 64 bytes
        // We pad the data_hash (usually 32 bytes SHA256) to 64 bytes
        let mut report_data = [0u8; 64];
        if data_hash.len() > 64 {
            return Err(anyhow!("Data hash too long for TDX Report Data (max 64 bytes)"));
        }
        report_data[..data_hash.len()].copy_from_slice(data_hash);
        
        let inblob_path = format!("{}/inblob", report_dir);
        fs::write(&inblob_path, report_data)?;

        // 4. Read the Quote (outblob)
        let outblob_path = format!("{}/outblob", report_dir);
        let raw_quote = fs::read(&outblob_path)?;

        // 5. Cleanup
        fs::remove_dir(&report_dir)?;

        // 6. Parse the Quote to extract measurement (Mock parsing for now as full DCAP parsing is complex)
        // In a real implementation, we would parse the SGX/TDX Quote Body
        // Offset 112 is typically where the Quote Body starts in V4 Quotes, and MRENCLAVE is inside
        let measurement = if raw_quote.len() > 200 {
            raw_quote[112..144].to_vec() // Arbitrary offset for demo, requires 'sgx-dcap-quote-rs' for real parsing
        } else {
            vec![]
        };

        Ok(AttestationQuote {
            quote_version: 4, // TDX usually produces V4/V5 quotes
            measurement,
            data_hash: data_hash.to_vec(),
            raw_quote,
        })
    }
}

// For development on non-TDX hardware, we provide a fallback
// that mimics the structure but clearly indicates it's software-generated
pub struct FallbackAttestor {
    mock_key: rsa::RsaPrivateKey,
}

impl FallbackAttestor {
    pub fn new() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            mock_key: rsa::RsaPrivateKey::new(&mut rng, 2048).expect("key gen failed"),
        }
    }

    pub fn generate_quote(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        use rsa::pkcs8::EncodePublicKey;
        use rsa::traits::PublicKeyParts;
        
        // Simulate MRENCLAVE based on binary hash
        let measurement = Sha256::digest(b"BitSage-Node-Software-Mode").to_vec();
        
        // Create a fake "raw quote" which is just signature + data
        // This allows the rest of the pipeline to handle Vec<u8>
        Ok(AttestationQuote {
            quote_version: 0, // 0 = Software
            measurement,
            data_hash: data_hash.to_vec(),
            raw_quote: vec![0xFA, 0xCE], // Fake bytes
        })
    }
}

// Factory to get the best available attestor
pub enum TEEContext {
    Hardware(TdxAttestor),
    Software(FallbackAttestor),
}

impl TEEContext {
    pub fn new() -> Self {
        if Path::new(TSM_REPORT_PATH).exists() {
            TEEContext::Hardware(TdxAttestor::new())
        } else {
            println!("⚠️ TDX Hardware not found. Falling back to Software Attestation.");
            TEEContext::Software(FallbackAttestor::new())
        }
    }

    pub fn generate_quote(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        match self {
            TEEContext::Hardware(a) => a.generate_quote(data_hash),
            TEEContext::Software(a) => a.generate_quote(data_hash),
        }
    }
}
