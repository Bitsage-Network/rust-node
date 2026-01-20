//! GPU Monitoring Module
//!
//! Provides real-time GPU metrics using NVIDIA NVML (NVIDIA Management Library).
//! Falls back to mock data when NVML is not available.

pub mod nvml_monitor;

pub use nvml_monitor::{GpuMonitor, GpuMetrics, GpuError};

use anyhow::Result;

/// GPU tier classification based on VRAM and compute capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GpuTier {
    /// Consumer-grade GPUs (RTX 3060, 3070, 3080, etc.)
    Consumer,
    /// Professional GPUs (RTX 4090, A4000, A5000, etc.)
    Professional,
    /// Enterprise GPUs (A6000, A40, etc.)
    Enterprise,
    /// Data center GPUs (H100, A100, V100, etc.)
    DataCenter,
}

impl GpuTier {
    /// Classify GPU tier based on VRAM and model name
    pub fn from_vram_and_model(vram_gb: f32, model: &str) -> Self {
        let model_lower = model.to_lowercase();

        // Data center GPUs
        if model_lower.contains("h100")
            || model_lower.contains("a100")
            || model_lower.contains("v100")
            || model_lower.contains("mi250")
            || model_lower.contains("mi300")
        {
            return GpuTier::DataCenter;
        }

        // Enterprise GPUs
        if model_lower.contains("a6000")
            || model_lower.contains("a40")
            || model_lower.contains("rtx 6000")
            || (model_lower.contains("quadro") && vram_gb >= 32.0)
        {
            return GpuTier::Enterprise;
        }

        // Professional GPUs
        if model_lower.contains("rtx 4090")
            || model_lower.contains("rtx 5090")
            || model_lower.contains("a5000")
            || model_lower.contains("a4000")
            || (model_lower.contains("rtx") && vram_gb >= 20.0)
        {
            return GpuTier::Professional;
        }

        // Consumer by default
        GpuTier::Consumer
    }

    /// Get tier as string for API responses
    pub fn as_str(&self) -> &'static str {
        match self {
            GpuTier::Consumer => "Consumer",
            GpuTier::Professional => "Professional",
            GpuTier::Enterprise => "Enterprise",
            GpuTier::DataCenter => "DataCenter",
        }
    }
}

/// Initialize GPU monitoring
///
/// Returns a GPU monitor instance if NVML is available and GPUs are detected.
/// Returns None if no NVIDIA GPUs are available (will use mock data).
pub fn initialize_gpu_monitor() -> Result<Option<GpuMonitor>> {
    GpuMonitor::new()
}
