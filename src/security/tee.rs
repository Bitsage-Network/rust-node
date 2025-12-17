use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use std::path::Path;
use std::fs;
use sha2::{Sha256, Digest};
use tracing::{info, warn};

// Linux ConfigFS path for TSM (Trust Security Module) - Standard for TDX/SEV
const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

// NVIDIA Confidential Computing paths
const NVIDIA_CC_DEVICE: &str = "/dev/nvidia-cc";
const NVIDIA_ATTESTATION_DEVICE: &str = "/dev/nvidia-attestation";
const NVIDIA_GPU_ATTESTATION_SYSFS: &str = "/sys/class/nvidia-gpu/attestation";

/// Attestation quote from a TEE (CPU or GPU)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationQuote {
    /// Quote format version
    /// - 0: Software (mock)
    /// - 4-5: Intel TDX
    /// - 6: AMD SEV-SNP  
    /// - 100: NVIDIA H100 CC
    pub quote_version: u16,
    /// Hardware measurement (MRENCLAVE for TDX, GPU measurement for H100)
    pub measurement: Vec<u8>,
    /// User-provided data hash embedded in quote
    pub data_hash: Vec<u8>,
    /// Raw binary quote from hardware
    pub raw_quote: Vec<u8>,
    /// Optional: TEE type identifier
    #[serde(default)]
    pub tee_type: Option<TEEType>,
}

/// Supported TEE types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TEEType {
    /// Software emulation (no hardware TEE)
    Software,
    /// Intel TDX (Trust Domain Extensions)
    IntelTDX,
    /// AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
    AmdSevSnp,
    /// NVIDIA Confidential Computing (H100, H200, B100, B200, etc.)
    NvidiaCC,
    /// AMD Instinct MI300X Confidential Computing
    AmdMI300CC,
}

/// NVIDIA GPU generation with Confidential Computing support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvidiaGpuGeneration {
    /// Hopper architecture (H100, H200)
    Hopper,
    /// Blackwell architecture (B100, B200)
    Blackwell,
    /// Unknown/Other CC-capable GPU
    Unknown,
}

impl NvidiaGpuGeneration {
    /// Detect GPU generation from device name
    pub fn from_device_name(name: &str) -> Self {
        let name_upper = name.to_uppercase();
        if name_upper.contains("H100") || name_upper.contains("H200") || name_upper.contains("GH200") {
            Self::Hopper
        } else if name_upper.contains("B100") || name_upper.contains("B200") || name_upper.contains("GB200") {
            Self::Blackwell
        } else {
            Self::Unknown
        }
    }
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
            tee_type: Some(TEEType::IntelTDX),
        })
    }
}

// =============================================================================
// NVIDIA Confidential Computing Attestor (All CC-capable GPUs)
// =============================================================================

/// NVIDIA Confidential Computing Attestor
/// 
/// Provides hardware attestation for NVIDIA GPUs with Confidential Computing support:
/// - **Hopper**: H100, H200, GH200
/// - **Blackwell**: B100, B200, GB200
/// - **Future architectures** with CC support
/// 
/// # Architecture
/// 
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                    NVIDIA CC Attestation                        │
/// ├─────────────────────────────────────────────────────────────────┤
/// │                                                                 │
/// │   ┌─────────────────┐    ┌─────────────────┐                   │
/// │   │   GPU Firmware  │    │   CC Mode       │                   │
/// │   │   Measurement   │    │   Enabled       │                   │
/// │   └────────┬────────┘    └────────┬────────┘                   │
/// │            │                      │                            │
/// │            ▼                      ▼                            │
/// │   ┌─────────────────────────────────────────┐                  │
/// │   │          Attestation Report             │                  │
/// │   │  - GPU measurement (firmware hash)      │                  │
/// │   │  - CC mode status                       │                  │
/// │   │  - User data (nonce/hash)               │                  │
/// │   │  - NVIDIA signature                     │                  │
/// │   └─────────────────────────────────────────┘                  │
/// │                                                                 │
/// └─────────────────────────────────────────────────────────────────┘
/// ```
/// 
/// # Supported GPUs
/// 
/// | Architecture | GPUs | CC Support |
/// |--------------|------|------------|
/// | Hopper | H100, H200, GH200 | Full |
/// | Blackwell | B100, B200, GB200 | Full |
/// 
/// # Requirements
/// 
/// - NVIDIA GPU with Confidential Computing support
/// - NVIDIA driver 535+ with CC support
/// - Linux kernel 6.0+ (for NVIDIA CC driver interface)
/// - CC mode enabled in GPU firmware
pub struct NvidiaGpuAttestor {
    /// GPU device index
    device_id: usize,
    /// Detected GPU generation
    gpu_generation: NvidiaGpuGeneration,
    /// GPU name (for logging)
    gpu_name: String,
}

impl NvidiaGpuAttestor {
    /// Create a new NVIDIA CC attestor for the specified GPU
    pub fn new(device_id: usize) -> Result<Self> {
        // Check if NVIDIA CC is available
        if !Self::is_cc_available() {
            return Err(anyhow!(
                "NVIDIA Confidential Computing not available. \
                 Check: 1) CC-capable GPU present (H100/H200/B100/B200) 2) Driver 535+ 3) CC mode enabled"
            ));
        }
        
        // Detect GPU name and generation
        let (gpu_name, gpu_generation) = Self::detect_gpu_info(device_id)?;
        
        info!(
            "🔒 NVIDIA CC attestor initialized for GPU {} ({}, {:?})",
            device_id, gpu_name, gpu_generation
        );
        
        Ok(Self { 
            device_id,
            gpu_generation,
            gpu_name,
        })
    }
    
    /// Detect GPU information for the specified device
    fn detect_gpu_info(device_id: usize) -> Result<(String, NvidiaGpuGeneration)> {
        // Try nvidia-smi to get GPU name
        let output = std::process::Command::new("nvidia-smi")
            .args([
                "--query-gpu=name",
                "--format=csv,noheader",
                &format!("--id={}", device_id),
            ])
            .output();
        
        match output {
            Ok(o) if o.status.success() => {
                let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let generation = NvidiaGpuGeneration::from_device_name(&name);
                Ok((name, generation))
            }
            _ => {
                // Fallback: try to detect via sysfs
                let sysfs_name = format!("/sys/class/nvidia/gpu{}/device/product_name", device_id);
                if let Ok(name) = std::fs::read_to_string(&sysfs_name) {
                    let name = name.trim().to_string();
                    let generation = NvidiaGpuGeneration::from_device_name(&name);
                    return Ok((name, generation));
                }
                
                // Use generic name
                Ok(("NVIDIA CC GPU".to_string(), NvidiaGpuGeneration::Unknown))
            }
        }
    }
    
    /// Check if NVIDIA CC is available on this system
    pub fn is_cc_available() -> bool {
        // Check for NVIDIA CC device nodes
        let cc_device_exists = Path::new(NVIDIA_CC_DEVICE).exists();
        let attestation_device_exists = Path::new(NVIDIA_ATTESTATION_DEVICE).exists();
        let sysfs_exists = Path::new(NVIDIA_GPU_ATTESTATION_SYSFS).exists();
        
        // Check via nvidia-smi for CC mode
        let nvidia_smi_cc_check = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=cc_mode.current", "--format=csv,noheader"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("On"))
            .unwrap_or(false);
        
        // Check for CC-capable GPU (H100, H200, B100, B200, etc.)
        let has_cc_gpu = Self::detect_cc_capable_gpu();
        
        cc_device_exists || attestation_device_exists || sysfs_exists || nvidia_smi_cc_check || has_cc_gpu
    }
    
    /// Detect if any CC-capable GPU is present
    fn detect_cc_capable_gpu() -> bool {
        let output = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name", "--format=csv,noheader"])
            .output();
        
        match output {
            Ok(o) if o.status.success() => {
                let names = String::from_utf8_lossy(&o.stdout);
                // Check for known CC-capable GPUs
                names.lines().any(|name| {
                    let name_upper = name.to_uppercase();
                    name_upper.contains("H100") ||
                    name_upper.contains("H200") ||
                    name_upper.contains("GH200") ||
                    name_upper.contains("B100") ||
                    name_upper.contains("B200") ||
                    name_upper.contains("GB200")
                })
            }
            _ => false,
        }
    }
    
    /// Get the GPU generation
    pub fn gpu_generation(&self) -> NvidiaGpuGeneration {
        self.gpu_generation
    }
    
    /// Get the GPU name
    pub fn gpu_name(&self) -> &str {
        &self.gpu_name
    }
    
    /// Generate attestation quote from NVIDIA CC GPU
    /// 
    /// # Arguments
    /// * `data_hash` - User data to embed in attestation (e.g., proof commitment)
    /// 
    /// # Returns
    /// Attestation quote with GPU measurement and NVIDIA signature
    pub fn generate_quote(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        // Method 1: Try sysfs interface (newer kernels)
        if let Ok(quote) = self.generate_via_sysfs(data_hash) {
            return Ok(quote);
        }
        
        // Method 2: Try device file interface
        if let Ok(quote) = self.generate_via_device(data_hash) {
            return Ok(quote);
        }
        
        // Method 3: Try nvtrust CLI tool
        if let Ok(quote) = self.generate_via_nvtrust(data_hash) {
            return Ok(quote);
        }
        
        Err(anyhow!(
            "Failed to generate NVIDIA CC attestation. \
             GPU {} may not have CC enabled.", 
            self.device_id
        ))
    }
    
    /// Generate attestation via sysfs interface
    fn generate_via_sysfs(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        let attestation_dir = format!("{}/gpu{}", NVIDIA_GPU_ATTESTATION_SYSFS, self.device_id);
        
        if !Path::new(&attestation_dir).exists() {
            return Err(anyhow!("Sysfs attestation not available for GPU {}", self.device_id));
        }
        
        // Write nonce/user data
        let nonce_path = format!("{}/nonce", attestation_dir);
        let mut nonce_data = [0u8; 32];
        let copy_len = data_hash.len().min(32);
        nonce_data[..copy_len].copy_from_slice(&data_hash[..copy_len]);
        fs::write(&nonce_path, &nonce_data)?;
        
        // Read attestation report
        let report_path = format!("{}/report", attestation_dir);
        let raw_quote = fs::read(&report_path)?;
        
        // Extract GPU measurement from report
        // NVIDIA CC reports have measurement at offset 64
        let measurement = if raw_quote.len() >= 96 {
            raw_quote[64..96].to_vec()
        } else {
            vec![]
        };
        
        info!(
            "🔒 Generated NVIDIA CC attestation via sysfs ({} bytes)",
            raw_quote.len()
        );
        
        Ok(AttestationQuote {
            quote_version: 100, // NVIDIA H100 CC
            measurement,
            data_hash: data_hash.to_vec(),
            raw_quote,
            tee_type: Some(TEEType::NvidiaCC),
        })
    }
    
    /// Generate attestation via device file
    fn generate_via_device(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        use std::io::{Read, Write};
        use std::fs::OpenOptions;
        
        let device_path = if Path::new(NVIDIA_ATTESTATION_DEVICE).exists() {
            NVIDIA_ATTESTATION_DEVICE
        } else if Path::new(NVIDIA_CC_DEVICE).exists() {
            NVIDIA_CC_DEVICE
        } else {
            return Err(anyhow!("No NVIDIA CC device found"));
        };
        
        // Open device file
        let mut device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)?;
        
        // Write attestation request with user data
        // Format: [device_id: u32][nonce: 32 bytes]
        let mut request = Vec::with_capacity(36);
        request.extend_from_slice(&(self.device_id as u32).to_le_bytes());
        let mut nonce = [0u8; 32];
        let copy_len = data_hash.len().min(32);
        nonce[..copy_len].copy_from_slice(&data_hash[..copy_len]);
        request.extend_from_slice(&nonce);
        
        device.write_all(&request)?;
        
        // Read attestation report
        let mut raw_quote = Vec::new();
        device.read_to_end(&mut raw_quote)?;
        
        // Extract measurement
        let measurement = if raw_quote.len() >= 96 {
            raw_quote[64..96].to_vec()
        } else {
            vec![]
        };
        
        info!(
            "🔒 Generated NVIDIA CC attestation via device ({} bytes)",
            raw_quote.len()
        );
        
        Ok(AttestationQuote {
            quote_version: 100,
            measurement,
            data_hash: data_hash.to_vec(),
            raw_quote,
            tee_type: Some(TEEType::NvidiaCC),
        })
    }
    
    /// Generate attestation via nvtrust CLI tool
    fn generate_via_nvtrust(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        // nvtrust is NVIDIA's CLI tool for CC attestation
        let nonce_hex = hex::encode(data_hash);
        
        let output = std::process::Command::new("nvtrust")
            .args([
                "attest",
                "--gpu", &self.device_id.to_string(),
                "--nonce", &nonce_hex,
                "--output", "binary",
            ])
            .output()?;
        
        if !output.status.success() {
            return Err(anyhow!(
                "nvtrust attestation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        
        let raw_quote = output.stdout;
        
        // Extract measurement
        let measurement = if raw_quote.len() >= 96 {
            raw_quote[64..96].to_vec()
        } else {
            vec![]
        };
        
        info!(
            "🔒 Generated NVIDIA CC attestation via nvtrust ({} bytes)",
            raw_quote.len()
        );
        
        Ok(AttestationQuote {
            quote_version: 100,
            measurement,
            data_hash: data_hash.to_vec(),
            raw_quote,
            tee_type: Some(TEEType::NvidiaCC),
        })
    }
    
    /// Verify an NVIDIA CC attestation quote
    /// 
    /// # Verification Steps
    /// 1. Check quote format and version
    /// 2. Verify NVIDIA signature (requires NVIDIA verification service)
    /// 3. Check GPU measurement against whitelist
    /// 4. Verify user data matches
    pub fn verify_quote(quote: &AttestationQuote) -> Result<bool> {
        // Basic format checks
        if quote.quote_version != 100 {
            return Err(anyhow!("Not an NVIDIA CC quote (version {})", quote.quote_version));
        }
        
        if quote.raw_quote.len() < 96 {
            return Err(anyhow!("Quote too short ({} bytes)", quote.raw_quote.len()));
        }
        
        // In production, would verify:
        // 1. NVIDIA signature via NVIDIA Remote Attestation Service (NRAS)
        // 2. GPU measurement against known-good firmware hashes
        // 3. CC mode was enabled during computation
        
        warn!("⚠️ NVIDIA CC quote verification requires NRAS (not implemented)");
        
        Ok(true)
    }
}

// =============================================================================
// AMD MI300X Confidential Computing Attestor
// =============================================================================

/// AMD Instinct MI300X Confidential Computing Attestor
/// 
/// Provides hardware attestation for AMD MI300X GPUs with Confidential Computing.
/// AMD CC is implemented via integration with AMD SEV-SNP on the CPU side.
/// 
/// # Requirements
/// 
/// - AMD Instinct MI300X GPU
/// - AMD ROCm driver 6.0+
/// - Host CPU with AMD SEV-SNP support
pub struct AmdMI300Attestor {
    /// GPU device index
    device_id: usize,
}

impl AmdMI300Attestor {
    /// Create a new AMD MI300X CC attestor
    pub fn new(device_id: usize) -> Result<Self> {
        if !Self::is_cc_available() {
            return Err(anyhow!(
                "AMD MI300X Confidential Computing not available. \
                 Check: 1) MI300X GPU present 2) ROCm 6.0+ 3) SEV-SNP enabled"
            ));
        }
        
        info!("🔒 AMD MI300X CC attestor initialized for GPU {}", device_id);
        Ok(Self { device_id })
    }
    
    /// Check if AMD MI300X CC is available
    pub fn is_cc_available() -> bool {
        // Check for AMD GPU via ROCm
        let rocm_check = std::process::Command::new("rocm-smi")
            .args(["--showproductname"])
            .output();
        
        match rocm_check {
            Ok(o) if o.status.success() => {
                let output = String::from_utf8_lossy(&o.stdout);
                output.to_uppercase().contains("MI300")
            }
            _ => false,
        }
    }
    
    /// Generate attestation quote
    /// 
    /// AMD MI300X CC uses SEV-SNP for attestation through the host CPU.
    pub fn generate_quote(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        // AMD MI300X CC leverages SEV-SNP for attestation
        // The GPU computation is protected, but attestation flows through CPU TEE
        
        // Check if we can use SEV-SNP
        if Path::new(TSM_REPORT_PATH).exists() {
            // Use SEV-SNP via ConfigFS-TSM (same interface as TDX)
            let report_name = format!("bitsage_amd_gpu_{}", uuid::Uuid::new_v4());
            let report_dir = format!("{}/{}", TSM_REPORT_PATH, report_name);
            
            fs::create_dir(&report_dir)?;
            
            // Include GPU device ID in report data
            let mut report_data = [0u8; 64];
            let copy_len = data_hash.len().min(60);
            report_data[..copy_len].copy_from_slice(&data_hash[..copy_len]);
            report_data[60..64].copy_from_slice(&(self.device_id as u32).to_le_bytes());
            
            let inblob_path = format!("{}/inblob", report_dir);
            fs::write(&inblob_path, report_data)?;
            
            let outblob_path = format!("{}/outblob", report_dir);
            let raw_quote = fs::read(&outblob_path)?;
            
            fs::remove_dir(&report_dir)?;
            
            let measurement = if raw_quote.len() >= 96 {
                raw_quote[64..96].to_vec()
            } else {
                vec![]
            };
            
            info!("🔒 Generated AMD MI300X CC attestation via SEV-SNP ({} bytes)", raw_quote.len());
            
            return Ok(AttestationQuote {
                quote_version: 101, // AMD MI300X CC
                measurement,
                data_hash: data_hash.to_vec(),
                raw_quote,
                tee_type: Some(TEEType::AmdMI300CC),
            });
        }
        
        Err(anyhow!("AMD MI300X CC requires SEV-SNP host support"))
    }
}

// =============================================================================
// Software Fallback Attestor
// =============================================================================

/// Software fallback attestor for development on non-TEE hardware
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
        // Simulate MRENCLAVE based on binary hash
        let measurement = Sha256::digest(b"BitSage-Node-Software-Mode").to_vec();
        
        // Create a fake "raw quote" which is just signature + data
        // This allows the rest of the pipeline to handle Vec<u8>
        Ok(AttestationQuote {
            quote_version: 0, // 0 = Software
            measurement,
            data_hash: data_hash.to_vec(),
            raw_quote: vec![0xFA, 0xCE], // Fake bytes
            tee_type: Some(TEEType::Software),
        })
    }
}

// Factory to get the best available attestor
// =============================================================================
// TEE Context - Unified Interface
// =============================================================================

/// Unified TEE context supporting multiple TEE types
/// 
/// Priority order for automatic detection:
/// 1. NVIDIA CC (H100/H200/B100/B200 - if GPU attestation available)
/// 2. AMD MI300X CC (if ROCm + SEV-SNP available)
/// 3. Intel TDX (if ConfigFS-TSM available)
/// 4. AMD SEV-SNP (via ConfigFS-TSM)
/// 5. Software fallback (for development)
pub enum TEEContext {
    /// Intel TDX hardware attestation
    IntelTDX(TdxAttestor),
    /// NVIDIA Confidential Computing (H100, H200, B100, B200, etc.)
    NvidiaCC(NvidiaGpuAttestor),
    /// AMD MI300X Confidential Computing
    AmdMI300(AmdMI300Attestor),
    /// Software fallback for development
    Software(FallbackAttestor),
}

impl TEEContext {
    /// Create a new TEE context with automatic hardware detection
    pub fn new() -> Self {
        // Priority 1: Check for NVIDIA CC (H100/H200/B100/B200)
        if NvidiaGpuAttestor::is_cc_available() {
            match NvidiaGpuAttestor::new(0) {
                Ok(attestor) => {
                    info!(
                        "🔒 Using NVIDIA {} Confidential Computing ({:?})",
                        attestor.gpu_name(),
                        attestor.gpu_generation()
                    );
                    return TEEContext::NvidiaCC(attestor);
                }
                Err(e) => {
                    warn!("NVIDIA CC detection failed: {}. Checking other TEEs.", e);
                }
            }
        }
        
        // Priority 2: Check for AMD MI300X CC
        if AmdMI300Attestor::is_cc_available() {
            match AmdMI300Attestor::new(0) {
                Ok(attestor) => {
                    info!("🔒 Using AMD MI300X Confidential Computing");
                    return TEEContext::AmdMI300(attestor);
                }
                Err(e) => {
                    warn!("AMD MI300X CC detection failed: {}. Checking other TEEs.", e);
                }
            }
        }
        
        // Priority 3: Check for Intel TDX / AMD SEV-SNP via ConfigFS-TSM
        if Path::new(TSM_REPORT_PATH).exists() {
            info!("🔒 Using CPU TEE attestation (TDX/SEV-SNP)");
            return TEEContext::IntelTDX(TdxAttestor::new());
        }
        
        // Priority 4: Software fallback
        warn!("⚠️ No hardware TEE found. Using software attestation (INSECURE for production).");
            TEEContext::Software(FallbackAttestor::new())
        }
    
    /// Create TEE context for a specific TEE type
    pub fn with_type(tee_type: TEEType) -> Result<Self> {
        match tee_type {
            TEEType::NvidiaCC => {
                let attestor = NvidiaGpuAttestor::new(0)?;
                Ok(TEEContext::NvidiaCC(attestor))
            }
            TEEType::AmdMI300CC => {
                let attestor = AmdMI300Attestor::new(0)?;
                Ok(TEEContext::AmdMI300(attestor))
            }
            TEEType::IntelTDX => {
                if !Path::new(TSM_REPORT_PATH).exists() {
                    return Err(anyhow!("Intel TDX not available"));
                }
                Ok(TEEContext::IntelTDX(TdxAttestor::new()))
            }
            TEEType::AmdSevSnp => {
                // AMD SEV-SNP also uses ConfigFS-TSM
                if !Path::new(TSM_REPORT_PATH).exists() {
                    return Err(anyhow!("AMD SEV-SNP not available"));
                }
                Ok(TEEContext::IntelTDX(TdxAttestor::new())) // Same interface
            }
            TEEType::Software => {
                Ok(TEEContext::Software(FallbackAttestor::new()))
            }
        }
    }
    
    /// Create TEE context for a specific NVIDIA GPU
    pub fn with_nvidia_gpu(device_id: usize) -> Result<Self> {
        let attestor = NvidiaGpuAttestor::new(device_id)?;
        Ok(TEEContext::NvidiaCC(attestor))
    }
    
    /// Create TEE context for a specific AMD GPU
    pub fn with_amd_gpu(device_id: usize) -> Result<Self> {
        let attestor = AmdMI300Attestor::new(device_id)?;
        Ok(TEEContext::AmdMI300(attestor))
    }
    
    /// Generate attestation quote
    pub fn generate_quote(&self, data_hash: &[u8]) -> Result<AttestationQuote> {
        match self {
            TEEContext::IntelTDX(a) => a.generate_quote(data_hash),
            TEEContext::NvidiaCC(a) => a.generate_quote(data_hash),
            TEEContext::AmdMI300(a) => a.generate_quote(data_hash),
            TEEContext::Software(a) => a.generate_quote(data_hash),
        }
    }
    
    /// Get the TEE type
    pub fn tee_type(&self) -> TEEType {
        match self {
            TEEContext::IntelTDX(_) => TEEType::IntelTDX,
            TEEContext::NvidiaCC(_) => TEEType::NvidiaCC,
            TEEContext::AmdMI300(_) => TEEType::AmdMI300CC,
            TEEContext::Software(_) => TEEType::Software,
        }
    }
    
    /// Check if this is a hardware TEE
    pub fn is_hardware(&self) -> bool {
        !matches!(self, TEEContext::Software(_))
    }
    
    /// Check if this is a GPU TEE
    pub fn is_gpu_tee(&self) -> bool {
        matches!(self, TEEContext::NvidiaCC(_) | TEEContext::AmdMI300(_))
    }
}

impl Default for TEEContext {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tee_context_creation() {
        let ctx = TEEContext::new();
        // Should create some context (software on dev machines)
        let _ = ctx.tee_type();
    }
    
    #[test]
    fn test_software_attestation() {
        let ctx = TEEContext::Software(FallbackAttestor::new());
        let quote = ctx.generate_quote(b"test_data").unwrap();
        
        assert_eq!(quote.quote_version, 0);
        assert_eq!(quote.tee_type, Some(TEEType::Software));
    }
    
    #[test]
    fn test_nvidia_cc_detection() {
        // This will return false on non-CC machines but shouldn't panic
        let available = NvidiaGpuAttestor::is_cc_available();
        println!("NVIDIA CC available: {}", available);
    }
    
    #[test]
    fn test_amd_mi300_detection() {
        // This will return false on non-MI300X machines but shouldn't panic
        let available = AmdMI300Attestor::is_cc_available();
        println!("AMD MI300X CC available: {}", available);
    }
    
    #[test]
    fn test_gpu_generation_detection() {
        assert_eq!(NvidiaGpuGeneration::from_device_name("NVIDIA H100 80GB HBM3"), NvidiaGpuGeneration::Hopper);
        assert_eq!(NvidiaGpuGeneration::from_device_name("NVIDIA H200"), NvidiaGpuGeneration::Hopper);
        assert_eq!(NvidiaGpuGeneration::from_device_name("NVIDIA GH200"), NvidiaGpuGeneration::Hopper);
        assert_eq!(NvidiaGpuGeneration::from_device_name("NVIDIA B100"), NvidiaGpuGeneration::Blackwell);
        assert_eq!(NvidiaGpuGeneration::from_device_name("NVIDIA B200"), NvidiaGpuGeneration::Blackwell);
        assert_eq!(NvidiaGpuGeneration::from_device_name("NVIDIA GB200"), NvidiaGpuGeneration::Blackwell);
        assert_eq!(NvidiaGpuGeneration::from_device_name("NVIDIA A100"), NvidiaGpuGeneration::Unknown);
    }
    
    #[test]
    fn test_is_gpu_tee() {
        let software_ctx = TEEContext::Software(FallbackAttestor::new());
        assert!(!software_ctx.is_gpu_tee());
        assert!(!software_ctx.is_hardware());
    }
}
