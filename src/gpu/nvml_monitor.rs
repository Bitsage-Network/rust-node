//! NVIDIA GPU Monitoring via NVML
//!
//! Provides real-time GPU metrics using the NVIDIA Management Library.
//! Gracefully falls back when NVML is not available.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use tracing::{debug, warn, error};

#[cfg(feature = "gpu-metrics")]
use nvml_wrapper::Nvml;

/// GPU monitoring error
#[derive(Debug, thiserror::Error)]
pub enum GpuError {
    #[error("NVML not available: {0}")]
    NvmlNotAvailable(String),

    #[error("No NVIDIA GPUs detected")]
    NoGpusDetected,

    #[error("Failed to query GPU metrics: {0}")]
    QueryFailed(String),

    #[error("NVML feature not enabled")]
    FeatureDisabled,
}

/// Individual GPU metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMetrics {
    /// GPU index
    pub index: u32,

    /// GPU model name
    pub model: String,

    /// GPU tier classification
    pub tier: String,

    /// Total VRAM in GB
    pub vram_total_gb: f32,

    /// Used VRAM in GB
    pub vram_used_gb: f32,

    /// VRAM utilization percentage
    pub vram_utilization: f32,

    /// GPU compute utilization percentage (0-100)
    pub compute_utilization: f32,

    /// GPU temperature in Celsius
    pub temperature_celsius: f32,

    /// Power draw in watts
    pub power_watts: f32,

    /// Driver version
    pub driver_version: String,

    /// CUDA version (if available)
    pub cuda_version: Option<String>,

    /// Whether GPU has TEE support
    pub has_tee: bool,

    /// TEE type if available
    pub tee_type: Option<String>,

    /// Current job ID (if assigned)
    pub current_job_id: Option<String>,
}

/// GPU Monitor
pub struct GpuMonitor {
    #[cfg(feature = "gpu-metrics")]
    nvml: Nvml,

    #[cfg(not(feature = "gpu-metrics"))]
    _phantom: (),
}

impl GpuMonitor {
    /// Create a new GPU monitor
    ///
    /// Returns None if NVML is not available or no GPUs are detected.
    /// This allows the application to run without GPUs for testing.
    pub fn new() -> Result<Option<Self>> {
        #[cfg(feature = "gpu-metrics")]
        {
            match Nvml::init() {
                Ok(nvml) => {
                    match nvml.device_count() {
                        Ok(count) if count > 0 => {
                            debug!("NVML initialized successfully, detected {} GPU(s)", count);
                            Ok(Some(Self { nvml }))
                        }
                        Ok(_) => {
                            warn!("NVML initialized but no GPUs detected");
                            Ok(None)
                        }
                        Err(e) => {
                            warn!("Failed to get GPU count: {}", e);
                            Ok(None)
                        }
                    }
                }
                Err(e) => {
                    warn!("NVML initialization failed: {}, GPU metrics will not be available", e);
                    Ok(None)
                }
            }
        }

        #[cfg(not(feature = "gpu-metrics"))]
        {
            warn!("GPU metrics feature not enabled, compile with --features gpu-metrics");
            Ok(None)
        }
    }

    /// Get metrics for all GPUs
    pub fn get_all_gpus(&self) -> Result<Vec<GpuMetrics>> {
        #[cfg(feature = "gpu-metrics")]
        {
            let count = self.nvml.device_count()
                .map_err(|e| anyhow!("Failed to get device count: {}", e))?;

            let mut gpus = Vec::new();

            for i in 0..count {
                match self.get_gpu_metrics(i) {
                    Ok(metrics) => gpus.push(metrics),
                    Err(e) => {
                        error!("Failed to get metrics for GPU {}: {}", i, e);
                        // Continue with other GPUs
                    }
                }
            }

            Ok(gpus)
        }

        #[cfg(not(feature = "gpu-metrics"))]
        {
            Err(anyhow!(GpuError::FeatureDisabled))
        }
    }

    /// Get metrics for a specific GPU
    #[cfg(feature = "gpu-metrics")]
    fn get_gpu_metrics(&self, index: u32) -> Result<GpuMetrics> {
        let device = self.nvml.device_by_index(index)
            .map_err(|e| anyhow!("Failed to get device {}: {}", index, e))?;

        // Get GPU model name
        let model = device.name()
            .unwrap_or_else(|_| format!("Unknown GPU {}", index));

        // Get memory info
        let memory_info = device.memory_info()
            .map_err(|e| anyhow!("Failed to get memory info: {}", e))?;

        let vram_total_gb = memory_info.total as f32 / 1024.0 / 1024.0 / 1024.0;
        let vram_used_gb = memory_info.used as f32 / 1024.0 / 1024.0 / 1024.0;
        let vram_utilization = if memory_info.total > 0 {
            (memory_info.used as f32 / memory_info.total as f32) * 100.0
        } else {
            0.0
        };

        // Get utilization rates
        let utilization = device.utilization_rates()
            .unwrap_or_else(|_| nvml_wrapper::struct_wrappers::device::Utilization {
                gpu: 0,
                memory: 0,
            });

        let compute_utilization = utilization.gpu as f32;

        // Get temperature
        let temperature_celsius = device.temperature(nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu)
            .unwrap_or(0) as f32;

        // Get power draw
        let power_watts = device.power_usage()
            .map(|p| p as f32 / 1000.0)  // Convert mW to W
            .unwrap_or(0.0);

        // Get driver version
        let driver_version = self.nvml.sys_driver_version()
            .unwrap_or_else(|_| "Unknown".to_string());

        // Get CUDA version
        let cuda_version = self.nvml.sys_cuda_driver_version()
            .ok()
            .map(|v| {
                let major = v / 1000;
                let minor = (v % 1000) / 10;
                format!("{}.{}", major, minor)
            });

        // Detect TEE support (NVIDIA Confidential Computing)
        let (has_tee, tee_type) = Self::detect_tee_support(&model);

        // Classify GPU tier
        let tier = super::GpuTier::from_vram_and_model(vram_total_gb, &model);

        Ok(GpuMetrics {
            index,
            model,
            tier: tier.as_str().to_string(),
            vram_total_gb,
            vram_used_gb,
            vram_utilization,
            compute_utilization,
            temperature_celsius,
            power_watts,
            driver_version,
            cuda_version,
            has_tee,
            tee_type,
            current_job_id: None,  // Will be set by coordinator
        })
    }

    /// Detect if GPU supports TEE (Trusted Execution Environment)
    #[cfg(feature = "gpu-metrics")]
    fn detect_tee_support(model: &str) -> (bool, Option<String>) {
        let model_lower = model.to_lowercase();

        // NVIDIA Hopper (H100) has Confidential Computing
        if model_lower.contains("h100") {
            return (true, Some("NVIDIA Confidential Computing".to_string()));
        }

        // Check for other TEE-capable GPUs
        // A100 with MIG can support some confidential computing features
        if model_lower.contains("a100") {
            return (true, Some("NVIDIA MIG Isolation".to_string()));
        }

        (false, None)
    }

    /// Get count of available GPUs
    pub fn gpu_count(&self) -> Result<u32> {
        #[cfg(feature = "gpu-metrics")]
        {
            self.nvml.device_count()
                .map_err(|e| anyhow!("Failed to get device count: {}", e))
        }

        #[cfg(not(feature = "gpu-metrics"))]
        {
            Err(anyhow!(GpuError::FeatureDisabled))
        }
    }
}

/// Create mock GPU data for testing when NVML is not available
pub fn create_mock_gpu_metrics() -> Vec<GpuMetrics> {
    warn!("Using mock GPU data - NVML not available or no GPUs detected");

    vec![
        GpuMetrics {
            index: 0,
            model: "Mock GPU (NVML Not Available)".to_string(),
            tier: "Consumer".to_string(),
            vram_total_gb: 16.0,
            vram_used_gb: 4.0,
            vram_utilization: 25.0,
            compute_utilization: 0.0,
            temperature_celsius: 45.0,
            power_watts: 50.0,
            driver_version: "N/A".to_string(),
            cuda_version: None,
            has_tee: false,
            tee_type: None,
            current_job_id: None,
        }
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_tier_classification() {
        assert_eq!(
            super::super::GpuTier::from_vram_and_model(80.0, "NVIDIA H100"),
            super::super::GpuTier::DataCenter
        );

        assert_eq!(
            super::super::GpuTier::from_vram_and_model(24.0, "RTX 4090"),
            super::super::GpuTier::Professional
        );

        assert_eq!(
            super::super::GpuTier::from_vram_and_model(12.0, "RTX 3060"),
            super::super::GpuTier::Consumer
        );
    }

    #[test]
    fn test_mock_gpu_creation() {
        let gpus = create_mock_gpu_metrics();
        assert_eq!(gpus.len(), 1);
        assert!(gpus[0].model.contains("Mock"));
    }
}
