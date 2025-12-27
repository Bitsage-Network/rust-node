//! Comprehensive GPU Database
//!
//! Contains specifications and market pricing for all supported NVIDIA GPUs,
//! sourced from real market data (Shadeform, Lambda Labs, Crusoe, GCP, etc.)
//!
//! Last Updated: December 2024

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// GPU architecture generation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GpuArchitecture {
    /// Maxwell (2014)
    Maxwell,
    /// Pascal (2016)
    Pascal,
    /// Volta (2017)
    Volta,
    /// Turing (2018)
    Turing,
    /// Ampere (2020)
    Ampere,
    /// Ada Lovelace (2022)
    AdaLovelace,
    /// Hopper (2022)
    Hopper,
    /// Blackwell (2024)
    Blackwell,
}

/// GPU form factor / interconnect type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormFactor {
    /// PCIe card (standard)
    PCIe,
    /// SXM4 module (NVLink 3)
    SXM4,
    /// SXM5 module (NVLink 4)
    SXM5,
    /// SXM6 module (NVLink 5 - Blackwell)
    SXM6,
}

impl FormFactor {
    /// Get interconnect bandwidth in GB/s
    pub fn interconnect_bandwidth(&self) -> u32 {
        match self {
            FormFactor::PCIe => 64,      // PCIe Gen4 x16
            FormFactor::SXM4 => 600,     // NVLink 3
            FormFactor::SXM5 => 900,     // NVLink 4
            FormFactor::SXM6 => 1800,    // NVLink 5
        }
    }
}

/// Complete GPU specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuFullSpec {
    /// Model name
    pub model: String,
    /// Architecture
    pub architecture: GpuArchitecture,
    /// Form factor
    pub form_factor: FormFactor,
    /// VRAM in GB
    pub vram_gb: u32,
    /// Memory bandwidth in GB/s
    pub bandwidth_gb_s: u32,
    /// Memory type
    pub memory_type: String,
    /// CUDA cores
    pub cuda_cores: u32,
    /// Tensor cores (0 if none)
    pub tensor_cores: u32,
    /// TDP in watts
    pub tdp_watts: u32,
    /// FP32 TFLOPS
    pub fp32_tflops: f32,
    /// FP16 TFLOPS (Tensor)
    pub fp16_tflops: f32,
    /// Has ECC memory
    pub has_ecc: bool,
    /// Supports Multi-Instance GPU
    pub supports_mig: bool,
    /// Supports confidential computing
    pub supports_cc: bool,
    /// Release year
    pub release_year: u16,
}

/// Market price entry from a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketPrice {
    /// Provider name
    pub provider: String,
    /// Number of GPUs
    pub gpu_count: u32,
    /// Price per hour in USD
    pub price_per_hour: f64,
    /// Form factor (may differ from base spec)
    pub form_factor: FormFactor,
    /// System RAM in GB
    pub system_ram_gb: u32,
    /// CPU cores
    pub cpu_cores: u32,
    /// Has InfiniBand
    pub has_infiniband: bool,
}

/// GPU with market pricing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuWithPricing {
    pub spec: GpuFullSpec,
    pub prices: Vec<MarketPrice>,
}

impl GpuWithPricing {
    /// Get the cheapest price for a given GPU count
    pub fn cheapest_price(&self, gpu_count: u32) -> Option<&MarketPrice> {
        self.prices
            .iter()
            .filter(|p| p.gpu_count == gpu_count)
            .min_by(|a, b| a.price_per_hour.partial_cmp(&b.price_per_hour).unwrap())
    }

    /// Get price per GPU for a given count
    pub fn price_per_gpu(&self, gpu_count: u32) -> Option<f64> {
        self.cheapest_price(gpu_count)
            .map(|p| p.price_per_hour / gpu_count as f64)
    }

    /// Get bandwidth efficiency ($/TB/s/hr)
    pub fn bandwidth_efficiency(&self, gpu_count: u32) -> Option<f64> {
        self.price_per_gpu(gpu_count).map(|price| {
            let bandwidth_tb_s = self.spec.bandwidth_gb_s as f64 / 1000.0;
            price / bandwidth_tb_s
        })
    }
}

/// Comprehensive GPU database
pub struct GpuDatabase {
    gpus: HashMap<String, GpuWithPricing>,
}

impl GpuDatabase {
    /// Create a new GPU database with all known GPUs
    pub fn new() -> Self {
        let mut gpus = HashMap::new();

        // =========================================================================
        // BLACKWELL GENERATION (2024)
        // =========================================================================

        gpus.insert("B300".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "B300".to_string(),
                architecture: GpuArchitecture::Blackwell,
                form_factor: FormFactor::SXM6,
                vram_gb: 288,
                bandwidth_gb_s: 9000,  // Estimated HBM3e
                memory_type: "HBM3e".to_string(),
                cuda_cores: 23040,
                tensor_cores: 720,
                tdp_watts: 1200,
                fp32_tflops: 90.0,
                fp16_tflops: 1800.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: true,
                release_year: 2025,
            },
            prices: vec![
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 1, price_per_hour: 7.91, form_factor: FormFactor::SXM6, system_ram_gb: 275, cpu_cores: 30, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 4, price_per_hour: 25.73, form_factor: FormFactor::SXM6, system_ram_gb: 1097, cpu_cores: 120, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 8, price_per_hour: 49.49, form_factor: FormFactor::SXM6, system_ram_gb: 2202, cpu_cores: 240, has_infiniband: false },
            ],
        });

        gpus.insert("B200".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "B200".to_string(),
                architecture: GpuArchitecture::Blackwell,
                form_factor: FormFactor::SXM6,
                vram_gb: 192,
                bandwidth_gb_s: 8000,
                memory_type: "HBM3e".to_string(),
                cuda_cores: 20480,
                tensor_cores: 640,
                tdp_watts: 1000,
                fp32_tflops: 80.0,
                fp16_tflops: 1600.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: true,
                release_year: 2024,
            },
            prices: vec![
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 1, price_per_hour: 6.76, form_factor: FormFactor::SXM6, system_ram_gb: 184, cpu_cores: 31, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 4, price_per_hour: 21.12, form_factor: FormFactor::SXM6, system_ram_gb: 736, cpu_cores: 124, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 8, price_per_hour: 40.27, form_factor: FormFactor::SXM6, system_ram_gb: 1444, cpu_cores: 248, has_infiniband: false },
                MarketPrice { provider: "SHADEFORM".into(), gpu_count: 8, price_per_hour: 43.20, form_factor: FormFactor::SXM6, system_ram_gb: 1792, cpu_cores: 160, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 8, price_per_hour: 47.90, form_factor: FormFactor::SXM6, system_ram_gb: 2898, cpu_cores: 208, has_infiniband: false },
            ],
        });

        // =========================================================================
        // HOPPER GENERATION (2022-2023)
        // =========================================================================

        gpus.insert("H200".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "H200".to_string(),
                architecture: GpuArchitecture::Hopper,
                form_factor: FormFactor::SXM5,
                vram_gb: 141,
                bandwidth_gb_s: 4800,
                memory_type: "HBM3e".to_string(),
                cuda_cores: 16896,
                tensor_cores: 528,
                tdp_watts: 700,
                fp32_tflops: 67.0,
                fp16_tflops: 1979.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: true,
                release_year: 2024,
            },
            prices: vec![
                MarketPrice { provider: "SHADEFORM".into(), gpu_count: 1, price_per_hour: 2.94, form_factor: FormFactor::SXM5, system_ram_gb: 200, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "NEBIUS".into(), gpu_count: 1, price_per_hour: 3.36, form_factor: FormFactor::SXM5, system_ram_gb: 200, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "DIGITALOCEAN".into(), gpu_count: 1, price_per_hour: 4.13, form_factor: FormFactor::SXM5, system_ram_gb: 240, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 1, price_per_hour: 5.08, form_factor: FormFactor::SXM5, system_ram_gb: 185, cpu_cores: 44, has_infiniband: false },
                MarketPrice { provider: "SHADEFORM".into(), gpu_count: 8, price_per_hour: 21.60, form_factor: FormFactor::SXM5, system_ram_gb: 2048, cpu_cores: 96, has_infiniband: false },
                MarketPrice { provider: "BOOSTRUN".into(), gpu_count: 8, price_per_hour: 23.52, form_factor: FormFactor::SXM5, system_ram_gb: 2048, cpu_cores: 96, has_infiniband: false },
                MarketPrice { provider: "NEBIUS".into(), gpu_count: 8, price_per_hour: 26.88, form_factor: FormFactor::SXM5, system_ram_gb: 1597, cpu_cores: 128, has_infiniband: false },
                MarketPrice { provider: "DIGITALOCEAN".into(), gpu_count: 8, price_per_hour: 33.02, form_factor: FormFactor::SXM5, system_ram_gb: 1925, cpu_cores: 192, has_infiniband: false },
            ],
        });

        gpus.insert("H100 SXM".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "H100 SXM".to_string(),
                architecture: GpuArchitecture::Hopper,
                form_factor: FormFactor::SXM5,
                vram_gb: 80,
                bandwidth_gb_s: 3350,
                memory_type: "HBM3".to_string(),
                cuda_cores: 16896,
                tensor_cores: 528,
                tdp_watts: 700,
                fp32_tflops: 67.0,
                fp16_tflops: 1979.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: true,
                release_year: 2022,
            },
            prices: vec![
                MarketPrice { provider: "VOLTAGEPARK".into(), gpu_count: 1, price_per_hour: 2.39, form_factor: FormFactor::SXM5, system_ram_gb: 116, cpu_cores: 26, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 1, price_per_hour: 2.71, form_factor: FormFactor::SXM5, system_ram_gb: 120, cpu_cores: 30, has_infiniband: false },
                MarketPrice { provider: "NEBIUS".into(), gpu_count: 1, price_per_hour: 2.84, form_factor: FormFactor::SXM5, system_ram_gb: 200, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "CUDO".into(), gpu_count: 1, price_per_hour: 3.18, form_factor: FormFactor::SXM5, system_ram_gb: 59, cpu_cores: 12, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 1, price_per_hour: 3.95, form_factor: FormFactor::SXM5, system_ram_gb: 225, cpu_cores: 26, has_infiniband: false },
                MarketPrice { provider: "DIGITALOCEAN".into(), gpu_count: 1, price_per_hour: 4.01, form_factor: FormFactor::SXM5, system_ram_gb: 240, cpu_cores: 20, has_infiniband: false },
                MarketPrice { provider: "VOLTAGEPARK".into(), gpu_count: 2, price_per_hour: 4.78, form_factor: FormFactor::SXM5, system_ram_gb: 232, cpu_cores: 52, has_infiniband: false },
                MarketPrice { provider: "CUDO".into(), gpu_count: 2, price_per_hour: 7.61, form_factor: FormFactor::SXM5, system_ram_gb: 192, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 2, price_per_hour: 7.66, form_factor: FormFactor::SXM5, system_ram_gb: 450, cpu_cores: 52, has_infiniband: false },
                MarketPrice { provider: "VOLTAGEPARK".into(), gpu_count: 4, price_per_hour: 9.55, form_factor: FormFactor::SXM5, system_ram_gb: 464, cpu_cores: 104, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 4, price_per_hour: 14.83, form_factor: FormFactor::SXM5, system_ram_gb: 900, cpu_cores: 104, has_infiniband: false },
                MarketPrice { provider: "VOLTAGEPARK".into(), gpu_count: 8, price_per_hour: 19.10, form_factor: FormFactor::SXM5, system_ram_gb: 1024, cpu_cores: 104, has_infiniband: false },
                MarketPrice { provider: "NEBIUS".into(), gpu_count: 8, price_per_hour: 22.75, form_factor: FormFactor::SXM5, system_ram_gb: 1597, cpu_cores: 128, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 8, price_per_hour: 23.04, form_factor: FormFactor::SXM5, system_ram_gb: 960, cpu_cores: 192, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 8, price_per_hour: 28.70, form_factor: FormFactor::SXM5, system_ram_gb: 1802, cpu_cores: 208, has_infiniband: false },
                MarketPrice { provider: "DIGITALOCEAN".into(), gpu_count: 8, price_per_hour: 28.70, form_factor: FormFactor::SXM5, system_ram_gb: 1925, cpu_cores: 160, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 8, price_per_hour: 99.30, form_factor: FormFactor::SXM5, system_ram_gb: 1874, cpu_cores: 208, has_infiniband: false },
            ],
        });

        gpus.insert("H100 PCIe".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "H100 PCIe".to_string(),
                architecture: GpuArchitecture::Hopper,
                form_factor: FormFactor::PCIe,
                vram_gb: 80,
                bandwidth_gb_s: 2000,
                memory_type: "HBM3".to_string(),
                cuda_cores: 14592,
                tensor_cores: 456,
                tdp_watts: 350,
                fp32_tflops: 51.0,
                fp16_tflops: 1513.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: true,
                release_year: 2022,
            },
            prices: vec![
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 1, price_per_hour: 2.28, form_factor: FormFactor::PCIe, system_ram_gb: 180, cpu_cores: 28, has_infiniband: false },
                MarketPrice { provider: "IMWT".into(), gpu_count: 1, price_per_hour: 2.98, form_factor: FormFactor::PCIe, system_ram_gb: 128, cpu_cores: 20, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 1, price_per_hour: 2.99, form_factor: FormFactor::PCIe, system_ram_gb: 200, cpu_cores: 26, has_infiniband: false },
                MarketPrice { provider: "MASSEDCOMPUTE".into(), gpu_count: 1, price_per_hour: 3.58, form_factor: FormFactor::PCIe, system_ram_gb: 128, cpu_cores: 20, has_infiniband: false },
                MarketPrice { provider: "SCALEWAY".into(), gpu_count: 1, price_per_hour: 3.70, form_factor: FormFactor::PCIe, system_ram_gb: 240, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "PAPERSPACE".into(), gpu_count: 1, price_per_hour: 7.19, form_factor: FormFactor::PCIe, system_ram_gb: 268, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 2, price_per_hour: 4.56, form_factor: FormFactor::PCIe, system_ram_gb: 360, cpu_cores: 60, has_infiniband: false },
                MarketPrice { provider: "IMWT".into(), gpu_count: 2, price_per_hour: 5.95, form_factor: FormFactor::PCIe, system_ram_gb: 256, cpu_cores: 40, has_infiniband: false },
                MarketPrice { provider: "SCALEWAY".into(), gpu_count: 2, price_per_hour: 7.30, form_factor: FormFactor::PCIe, system_ram_gb: 480, cpu_cores: 48, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 4, price_per_hour: 9.12, form_factor: FormFactor::PCIe, system_ram_gb: 720, cpu_cores: 124, has_infiniband: false },
                MarketPrice { provider: "IMWT".into(), gpu_count: 4, price_per_hour: 11.90, form_factor: FormFactor::PCIe, system_ram_gb: 512, cpu_cores: 64, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 8, price_per_hour: 18.72, form_factor: FormFactor::PCIe, system_ram_gb: 1444, cpu_cores: 252, has_infiniband: false },
            ],
        });

        // =========================================================================
        // AMPERE GENERATION (2020-2022)
        // =========================================================================

        gpus.insert("A100 80GB SXM".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A100 80GB SXM".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::SXM4,
                vram_gb: 80,
                bandwidth_gb_s: 2039,
                memory_type: "HBM2e".to_string(),
                cuda_cores: 6912,
                tensor_cores: 432,
                tdp_watts: 400,
                fp32_tflops: 19.5,
                fp16_tflops: 312.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: false,
                release_year: 2020,
            },
            prices: vec![
                MarketPrice { provider: "MASSEDCOMPUTE".into(), gpu_count: 1, price_per_hour: 1.49, form_factor: FormFactor::SXM4, system_ram_gb: 100, cpu_cores: 14, has_infiniband: false },
                MarketPrice { provider: "DENVR".into(), gpu_count: 1, price_per_hour: 1.62, form_factor: FormFactor::SXM4, system_ram_gb: 116, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "CRUSOE".into(), gpu_count: 1, price_per_hour: 1.98, form_factor: FormFactor::SXM4, system_ram_gb: 120, cpu_cores: 12, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 1, price_per_hour: 2.18, form_factor: FormFactor::SXM4, system_ram_gb: 120, cpu_cores: 22, has_infiniband: false },
                MarketPrice { provider: "PAPERSPACE".into(), gpu_count: 1, price_per_hour: 3.94, form_factor: FormFactor::SXM4, system_ram_gb: 90, cpu_cores: 8, has_infiniband: false },
                MarketPrice { provider: "CRUSOE".into(), gpu_count: 2, price_per_hour: 3.96, form_factor: FormFactor::SXM4, system_ram_gb: 240, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 2, price_per_hour: 4.37, form_factor: FormFactor::SXM4, system_ram_gb: 240, cpu_cores: 44, has_infiniband: false },
                MarketPrice { provider: "CRUSOE".into(), gpu_count: 4, price_per_hour: 7.92, form_factor: FormFactor::SXM4, system_ram_gb: 480, cpu_cores: 48, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 4, price_per_hour: 8.74, form_factor: FormFactor::SXM4, system_ram_gb: 480, cpu_cores: 88, has_infiniband: false },
                MarketPrice { provider: "DENVR".into(), gpu_count: 8, price_per_hour: 12.96, form_factor: FormFactor::SXM4, system_ram_gb: 940, cpu_cores: 200, has_infiniband: false },
                MarketPrice { provider: "SHADEFORM".into(), gpu_count: 8, price_per_hour: 15.73, form_factor: FormFactor::SXM4, system_ram_gb: 1802, cpu_cores: 240, has_infiniband: false },
                MarketPrice { provider: "CRUSOE".into(), gpu_count: 8, price_per_hour: 15.84, form_factor: FormFactor::SXM4, system_ram_gb: 960, cpu_cores: 96, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 8, price_per_hour: 17.18, form_factor: FormFactor::SXM4, system_ram_gb: 1802, cpu_cores: 240, has_infiniband: false },
                MarketPrice { provider: "DATACRUNCH".into(), gpu_count: 8, price_per_hour: 17.47, form_factor: FormFactor::SXM4, system_ram_gb: 960, cpu_cores: 176, has_infiniband: false },
                MarketPrice { provider: "CRUSOE".into(), gpu_count: 8, price_per_hour: 18.72, form_factor: FormFactor::SXM4, system_ram_gb: 960, cpu_cores: 96, has_infiniband: true },
                MarketPrice { provider: "PAPERSPACE".into(), gpu_count: 8, price_per_hour: 30.91, form_factor: FormFactor::SXM4, system_ram_gb: 720, cpu_cores: 96, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 8, price_per_hour: 48.27, form_factor: FormFactor::SXM4, system_ram_gb: 1363, cpu_cores: 96, has_infiniband: false },
            ],
        });

        gpus.insert("A100 80GB PCIe".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A100 80GB PCIe".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 80,
                bandwidth_gb_s: 1935,
                memory_type: "HBM2e".to_string(),
                cuda_cores: 6912,
                tensor_cores: 432,
                tdp_watts: 300,
                fp32_tflops: 19.5,
                fp16_tflops: 312.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: false,
                release_year: 2020,
            },
            prices: vec![
                MarketPrice { provider: "MASSEDCOMPUTE".into(), gpu_count: 1, price_per_hour: 1.44, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 12, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 1, price_per_hour: 1.62, form_factor: FormFactor::PCIe, system_ram_gb: 120, cpu_cores: 28, has_infiniband: false },
                MarketPrice { provider: "CUDO".into(), gpu_count: 1, price_per_hour: 2.20, form_factor: FormFactor::PCIe, system_ram_gb: 48, cpu_cores: 12, has_infiniband: false },
                MarketPrice { provider: "MASSEDCOMPUTE".into(), gpu_count: 2, price_per_hour: 2.88, form_factor: FormFactor::PCIe, system_ram_gb: 128, cpu_cores: 30, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 2, price_per_hour: 3.24, form_factor: FormFactor::PCIe, system_ram_gb: 240, cpu_cores: 60, has_infiniband: false },
                MarketPrice { provider: "CUDO".into(), gpu_count: 2, price_per_hour: 4.39, form_factor: FormFactor::PCIe, system_ram_gb: 96, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "MASSEDCOMPUTE".into(), gpu_count: 4, price_per_hour: 5.76, form_factor: FormFactor::PCIe, system_ram_gb: 256, cpu_cores: 54, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 4, price_per_hour: 6.48, form_factor: FormFactor::PCIe, system_ram_gb: 480, cpu_cores: 124, has_infiniband: false },
                MarketPrice { provider: "CUDO".into(), gpu_count: 4, price_per_hour: 8.78, form_factor: FormFactor::PCIe, system_ram_gb: 192, cpu_cores: 48, has_infiniband: false },
                MarketPrice { provider: "HYPERSTACK".into(), gpu_count: 8, price_per_hour: 12.96, form_factor: FormFactor::PCIe, system_ram_gb: 1444, cpu_cores: 252, has_infiniband: false },
            ],
        });

        gpus.insert("A100 40GB SXM".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A100 40GB SXM".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::SXM4,
                vram_gb: 40,
                bandwidth_gb_s: 1555,
                memory_type: "HBM2".to_string(),
                cuda_cores: 6912,
                tensor_cores: 432,
                tdp_watts: 400,
                fp32_tflops: 19.5,
                fp16_tflops: 312.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: false,
                release_year: 2020,
            },
            prices: vec![
                MarketPrice { provider: "DENVR".into(), gpu_count: 1, price_per_hour: 1.50, form_factor: FormFactor::SXM4, system_ram_gb: 117, cpu_cores: 14, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 1, price_per_hour: 1.55, form_factor: FormFactor::SXM4, system_ram_gb: 200, cpu_cores: 30, has_infiniband: false },
                MarketPrice { provider: "PAPERSPACE".into(), gpu_count: 1, price_per_hour: 3.83, form_factor: FormFactor::SXM4, system_ram_gb: 90, cpu_cores: 8, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 1, price_per_hour: 4.41, form_factor: FormFactor::SXM4, system_ram_gb: 85, cpu_cores: 12, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 2, price_per_hour: 8.82, form_factor: FormFactor::SXM4, system_ram_gb: 170, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "DENVR".into(), gpu_count: 8, price_per_hour: 12.00, form_factor: FormFactor::SXM4, system_ram_gb: 940, cpu_cores: 120, has_infiniband: false },
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 8, price_per_hour: 12.38, form_factor: FormFactor::SXM4, system_ram_gb: 1802, cpu_cores: 124, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 4, price_per_hour: 17.63, form_factor: FormFactor::SXM4, system_ram_gb: 340, cpu_cores: 48, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 8, price_per_hour: 35.26, form_factor: FormFactor::SXM4, system_ram_gb: 680, cpu_cores: 96, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 16, price_per_hour: 66.89, form_factor: FormFactor::SXM4, system_ram_gb: 1363, cpu_cores: 96, has_infiniband: false },
            ],
        });

        gpus.insert("A100 40GB PCIe".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A100 40GB PCIe".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 40,
                bandwidth_gb_s: 1555,
                memory_type: "HBM2".to_string(),
                cuda_cores: 6912,
                tensor_cores: 432,
                tdp_watts: 250,
                fp32_tflops: 19.5,
                fp16_tflops: 312.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: false,
                release_year: 2020,
            },
            prices: vec![
                MarketPrice { provider: "LAMBDA-LABS".into(), gpu_count: 1, price_per_hour: 1.55, form_factor: FormFactor::PCIe, system_ram_gb: 200, cpu_cores: 30, has_infiniband: false },
            ],
        });

        gpus.insert("L40S".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "L40S".to_string(),
                architecture: GpuArchitecture::AdaLovelace,
                form_factor: FormFactor::PCIe,
                vram_gb: 48,
                bandwidth_gb_s: 864,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 18176,
                tensor_cores: 568,
                tdp_watts: 350,
                fp32_tflops: 91.6,
                fp16_tflops: 362.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2023,
            },
            prices: vec![
                MarketPrice { provider: "VULTR".into(), gpu_count: 1, price_per_hour: 0.85, form_factor: FormFactor::PCIe, system_ram_gb: 120, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "SHADEFORM".into(), gpu_count: 1, price_per_hour: 1.20, form_factor: FormFactor::PCIe, system_ram_gb: 120, cpu_cores: 24, has_infiniband: false },
                MarketPrice { provider: "COREWEAVE".into(), gpu_count: 1, price_per_hour: 1.45, form_factor: FormFactor::PCIe, system_ram_gb: 128, cpu_cores: 32, has_infiniband: false },
            ],
        });

        gpus.insert("L40".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "L40".to_string(),
                architecture: GpuArchitecture::AdaLovelace,
                form_factor: FormFactor::PCIe,
                vram_gb: 48,
                bandwidth_gb_s: 864,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 18176,
                tensor_cores: 568,
                tdp_watts: 300,
                fp32_tflops: 90.5,
                fp16_tflops: 181.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2023,
            },
            prices: vec![
                MarketPrice { provider: "SHADEFORM".into(), gpu_count: 1, price_per_hour: 0.95, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
            ],
        });

        gpus.insert("A40".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A40".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 48,
                bandwidth_gb_s: 696,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 10752,
                tensor_cores: 336,
                tdp_watts: 300,
                fp32_tflops: 37.4,
                fp16_tflops: 149.7,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2021,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.35, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.44, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
            ],
        });

        gpus.insert("A30".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A30".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 933,
                memory_type: "HBM2".to_string(),
                cuda_cores: 3584,
                tensor_cores: 224,
                tdp_watts: 165,
                fp32_tflops: 10.3,
                fp16_tflops: 165.0,
                has_ecc: true,
                supports_mig: true,
                supports_cc: false,
                release_year: 2021,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.25, form_factor: FormFactor::PCIe, system_ram_gb: 32, cpu_cores: 8, has_infiniband: false },
            ],
        });

        gpus.insert("A10".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A10".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 600,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 9216,
                tensor_cores: 288,
                tdp_watts: 150,
                fp32_tflops: 31.2,
                fp16_tflops: 125.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2021,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.20, form_factor: FormFactor::PCIe, system_ram_gb: 32, cpu_cores: 8, has_infiniband: false },
                MarketPrice { provider: "AWS".into(), gpu_count: 1, price_per_hour: 1.01, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 8, has_infiniband: false },
            ],
        });

        gpus.insert("A10G".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A10G".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 600,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 9216,
                tensor_cores: 288,
                tdp_watts: 150,
                fp32_tflops: 31.2,
                fp16_tflops: 125.0,
                has_ecc: false,
                supports_mig: false,
                supports_cc: false,
                release_year: 2021,
            },
            prices: vec![
                MarketPrice { provider: "AWS".into(), gpu_count: 1, price_per_hour: 1.21, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 8, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.28, form_factor: FormFactor::PCIe, system_ram_gb: 32, cpu_cores: 8, has_infiniband: false },
            ],
        });

        gpus.insert("A16".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A16".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 64, // 4x16GB
                bandwidth_gb_s: 231, // Per GPU
                memory_type: "GDDR6".to_string(),
                cuda_cores: 2560, // Per GPU
                tensor_cores: 80,
                tdp_watts: 250,
                fp32_tflops: 8.7, // Per GPU
                fp16_tflops: 34.8,
                has_ecc: false,
                supports_mig: false,
                supports_cc: false,
                release_year: 2021,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.40, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
            ],
        });

        gpus.insert("L4".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "L4".to_string(),
                architecture: GpuArchitecture::AdaLovelace,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 300,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 7424,
                tensor_cores: 232,
                tdp_watts: 72,
                fp32_tflops: 30.3,
                fp16_tflops: 121.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2023,
            },
            prices: vec![
                MarketPrice { provider: "GCP".into(), gpu_count: 1, price_per_hour: 0.81, form_factor: FormFactor::PCIe, system_ram_gb: 32, cpu_cores: 8, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.24, form_factor: FormFactor::PCIe, system_ram_gb: 24, cpu_cores: 6, has_infiniband: false },
            ],
        });

        // =========================================================================
        // TURING GENERATION (2018-2020)
        // =========================================================================

        gpus.insert("T4".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "T4".to_string(),
                architecture: GpuArchitecture::Turing,
                form_factor: FormFactor::PCIe,
                vram_gb: 16,
                bandwidth_gb_s: 320,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 2560,
                tensor_cores: 320,
                tdp_watts: 70,
                fp32_tflops: 8.1,
                fp16_tflops: 65.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2018,
            },
            prices: vec![
                MarketPrice { provider: "GCP".into(), gpu_count: 1, price_per_hour: 0.35, form_factor: FormFactor::PCIe, system_ram_gb: 16, cpu_cores: 4, has_infiniband: false },
                MarketPrice { provider: "AWS".into(), gpu_count: 1, price_per_hour: 0.53, form_factor: FormFactor::PCIe, system_ram_gb: 16, cpu_cores: 4, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.10, form_factor: FormFactor::PCIe, system_ram_gb: 16, cpu_cores: 4, has_infiniband: false },
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.08, form_factor: FormFactor::PCIe, system_ram_gb: 16, cpu_cores: 4, has_infiniband: false },
            ],
        });

        // =========================================================================
        // VOLTA GENERATION (2017-2018)
        // =========================================================================

        gpus.insert("V100 SXM2".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "V100 SXM2".to_string(),
                architecture: GpuArchitecture::Volta,
                form_factor: FormFactor::SXM4, // Using SXM4 as approximation
                vram_gb: 32,
                bandwidth_gb_s: 900,
                memory_type: "HBM2".to_string(),
                cuda_cores: 5120,
                tensor_cores: 640,
                tdp_watts: 300,
                fp32_tflops: 15.7,
                fp16_tflops: 125.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2017,
            },
            prices: vec![
                MarketPrice { provider: "AWS".into(), gpu_count: 1, price_per_hour: 3.06, form_factor: FormFactor::SXM4, system_ram_gb: 61, cpu_cores: 8, has_infiniband: false },
                MarketPrice { provider: "GCP".into(), gpu_count: 1, price_per_hour: 2.48, form_factor: FormFactor::SXM4, system_ram_gb: 52, cpu_cores: 8, has_infiniband: false },
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.20, form_factor: FormFactor::SXM4, system_ram_gb: 32, cpu_cores: 8, has_infiniband: false },
            ],
        });

        gpus.insert("V100 PCIe".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "V100 PCIe".to_string(),
                architecture: GpuArchitecture::Volta,
                form_factor: FormFactor::PCIe,
                vram_gb: 16,
                bandwidth_gb_s: 900,
                memory_type: "HBM2".to_string(),
                cuda_cores: 5120,
                tensor_cores: 640,
                tdp_watts: 250,
                fp32_tflops: 14.0,
                fp16_tflops: 112.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2017,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.15, form_factor: FormFactor::PCIe, system_ram_gb: 16, cpu_cores: 4, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.22, form_factor: FormFactor::PCIe, system_ram_gb: 32, cpu_cores: 8, has_infiniband: false },
            ],
        });

        // =========================================================================
        // PASCAL GENERATION (2016-2017)
        // =========================================================================

        gpus.insert("P4".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "P4".to_string(),
                architecture: GpuArchitecture::Pascal,
                form_factor: FormFactor::PCIe,
                vram_gb: 8,
                bandwidth_gb_s: 192,
                memory_type: "GDDR5".to_string(),
                cuda_cores: 2560,
                tensor_cores: 0,
                tdp_watts: 75,
                fp32_tflops: 5.5,
                fp16_tflops: 5.5,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2016,
            },
            prices: vec![
                MarketPrice { provider: "GCP".into(), gpu_count: 1, price_per_hour: 0.60, form_factor: FormFactor::PCIe, system_ram_gb: 8, cpu_cores: 2, has_infiniband: false },
            ],
        });

        // =========================================================================
        // MAXWELL GENERATION (2014-2016)
        // =========================================================================

        gpus.insert("M60".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "M60".to_string(),
                architecture: GpuArchitecture::Maxwell,
                form_factor: FormFactor::PCIe,
                vram_gb: 16, // 2x8GB
                bandwidth_gb_s: 160, // Per GPU
                memory_type: "GDDR5".to_string(),
                cuda_cores: 2048, // Per GPU
                tensor_cores: 0,
                tdp_watts: 300,
                fp32_tflops: 4.8,
                fp16_tflops: 4.8,
                has_ecc: false,
                supports_mig: false,
                supports_cc: false,
                release_year: 2015,
            },
            prices: vec![
                MarketPrice { provider: "AWS".into(), gpu_count: 1, price_per_hour: 1.03, form_factor: FormFactor::PCIe, system_ram_gb: 15, cpu_cores: 4, has_infiniband: false },
            ],
        });

        // =========================================================================
        // ADA LOVELACE PROFESSIONAL (2022-2023)
        // =========================================================================

        gpus.insert("RTX 6000 Ada".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "RTX 6000 Ada".to_string(),
                architecture: GpuArchitecture::AdaLovelace,
                form_factor: FormFactor::PCIe,
                vram_gb: 48,
                bandwidth_gb_s: 960,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 18176,
                tensor_cores: 568,
                tdp_watts: 300,
                fp32_tflops: 91.1,
                fp16_tflops: 182.2,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2022,
            },
            prices: vec![
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.65, form_factor: FormFactor::PCIe, system_ram_gb: 48, cpu_cores: 12, has_infiniband: false },
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.55, form_factor: FormFactor::PCIe, system_ram_gb: 48, cpu_cores: 12, has_infiniband: false },
            ],
        });

        gpus.insert("RTX Pro 6000".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "RTX Pro 6000".to_string(),
                architecture: GpuArchitecture::Blackwell, // Blackwell professional
                form_factor: FormFactor::PCIe,
                vram_gb: 96,
                bandwidth_gb_s: 1800,
                memory_type: "GDDR7".to_string(),
                cuda_cores: 24576,
                tensor_cores: 768,
                tdp_watts: 400,
                fp32_tflops: 100.0,
                fp16_tflops: 200.0,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2025,
            },
            prices: vec![
                MarketPrice { provider: "SHADEFORM".into(), gpu_count: 8, price_per_hour: 12.96, form_factor: FormFactor::PCIe, system_ram_gb: 1536, cpu_cores: 128, has_infiniband: false },
                MarketPrice { provider: "BOOSTRUN".into(), gpu_count: 8, price_per_hour: 15.84, form_factor: FormFactor::PCIe, system_ram_gb: 1536, cpu_cores: 128, has_infiniband: false },
            ],
        });

        gpus.insert("A6000".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A6000".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 48,
                bandwidth_gb_s: 768,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 10752,
                tensor_cores: 336,
                tdp_watts: 300,
                fp32_tflops: 38.7,
                fp16_tflops: 77.4,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2020,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.35, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.44, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
            ],
        });

        gpus.insert("A5000".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A5000".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 768,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 8192,
                tensor_cores: 256,
                tdp_watts: 230,
                fp32_tflops: 27.8,
                fp16_tflops: 55.6,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2021,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.28, form_factor: FormFactor::PCIe, system_ram_gb: 32, cpu_cores: 8, has_infiniband: false },
            ],
        });

        gpus.insert("A4000".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "A4000".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 16,
                bandwidth_gb_s: 448,
                memory_type: "GDDR6".to_string(),
                cuda_cores: 6144,
                tensor_cores: 192,
                tdp_watts: 140,
                fp32_tflops: 19.2,
                fp16_tflops: 38.4,
                has_ecc: true,
                supports_mig: false,
                supports_cc: false,
                release_year: 2021,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.15, form_factor: FormFactor::PCIe, system_ram_gb: 16, cpu_cores: 4, has_infiniband: false },
            ],
        });

        // =========================================================================
        // CONSUMER GPUs (For reference, typically not in cloud)
        // =========================================================================

        gpus.insert("RTX 4090".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "RTX 4090".to_string(),
                architecture: GpuArchitecture::AdaLovelace,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 1008,
                memory_type: "GDDR6X".to_string(),
                cuda_cores: 16384,
                tensor_cores: 512,
                tdp_watts: 450,
                fp32_tflops: 82.6,
                fp16_tflops: 165.2,
                has_ecc: false,
                supports_mig: false,
                supports_cc: false,
                release_year: 2022,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.35, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.44, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
            ],
        });

        gpus.insert("RTX 3090".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "RTX 3090".to_string(),
                architecture: GpuArchitecture::Ampere,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 936,
                memory_type: "GDDR6X".to_string(),
                cuda_cores: 10496,
                tensor_cores: 328,
                tdp_watts: 350,
                fp32_tflops: 35.6,
                fp16_tflops: 71.2,
                has_ecc: false,
                supports_mig: false,
                supports_cc: false,
                release_year: 2020,
            },
            prices: vec![
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.18, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
                MarketPrice { provider: "RUNPOD".into(), gpu_count: 1, price_per_hour: 0.22, form_factor: FormFactor::PCIe, system_ram_gb: 64, cpu_cores: 16, has_infiniband: false },
            ],
        });

        gpus.insert("RTX 5090".to_string(), GpuWithPricing {
            spec: GpuFullSpec {
                model: "RTX 5090".to_string(),
                architecture: GpuArchitecture::Blackwell,
                form_factor: FormFactor::PCIe,
                vram_gb: 32,
                bandwidth_gb_s: 1792,
                memory_type: "GDDR7".to_string(),
                cuda_cores: 21760,
                tensor_cores: 680,
                tdp_watts: 575,
                fp32_tflops: 104.0,
                fp16_tflops: 208.0,
                has_ecc: false,
                supports_mig: false,
                supports_cc: false,
                release_year: 2025,
            },
            prices: vec![
                // Projected pricing
                MarketPrice { provider: "VASTAI".into(), gpu_count: 1, price_per_hour: 0.75, form_factor: FormFactor::PCIe, system_ram_gb: 128, cpu_cores: 32, has_infiniband: false },
            ],
        });

        Self { gpus }
    }

    /// Get a GPU by model name
    pub fn get(&self, model: &str) -> Option<&GpuWithPricing> {
        self.gpus.get(model)
    }

    /// Get all GPUs
    pub fn all(&self) -> impl Iterator<Item = &GpuWithPricing> {
        self.gpus.values()
    }

    /// Get GPUs by architecture
    pub fn by_architecture(&self, arch: GpuArchitecture) -> Vec<&GpuWithPricing> {
        self.gpus
            .values()
            .filter(|g| g.spec.architecture == arch)
            .collect()
    }

    /// Get GPUs with minimum VRAM
    pub fn with_min_vram(&self, min_vram_gb: u32) -> Vec<&GpuWithPricing> {
        self.gpus
            .values()
            .filter(|g| g.spec.vram_gb >= min_vram_gb)
            .collect()
    }

    /// Get GPUs sorted by bandwidth efficiency (cheapest $/TB/s)
    pub fn by_bandwidth_efficiency(&self, gpu_count: u32) -> Vec<(&GpuWithPricing, f64)> {
        let mut results: Vec<_> = self.gpus
            .values()
            .filter_map(|g| {
                g.bandwidth_efficiency(gpu_count).map(|eff| (g, eff))
            })
            .collect();
        
        results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        results
    }

    /// Get GPU count
    pub fn count(&self) -> usize {
        self.gpus.len()
    }

    /// Find the cheapest GPU for a given proof size (log2)
    pub fn cheapest_for_proof_size(&self, log_size: u32, gpu_count: u32) -> Option<(&GpuWithPricing, f64)> {
        // Estimate VRAM needed: ~4 bytes per element for M31 field
        let elements = 1u64 << log_size;
        let vram_needed_gb = ((elements * 4) / (1024 * 1024 * 1024)) as u32 + 1;

        self.gpus
            .values()
            .filter(|g| g.spec.vram_gb >= vram_needed_gb)
            .filter_map(|g| {
                g.price_per_gpu(gpu_count).map(|price| (g, price))
            })
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
    }

    /// Print a formatted comparison table
    pub fn print_comparison_table(&self) {
        let mut gpus: Vec<_> = self.gpus.values().collect();
        gpus.sort_by(|a, b| {
            b.spec.bandwidth_gb_s.cmp(&a.spec.bandwidth_gb_s)
        });

        info!("GPU pricing comparison - {} models available", gpus.len());

        for gpu in gpus {
            let price_1 = gpu.cheapest_price(1)
                .map(|p| p.price_per_hour)
                .unwrap_or(0.0);
            let price_8 = gpu.cheapest_price(8)
                .map(|p| p.price_per_hour)
                .unwrap_or(0.0);
            let efficiency = gpu.bandwidth_efficiency(1)
                .unwrap_or(0.0);

            info!(
                model = %gpu.spec.model,
                vram_gb = gpu.spec.vram_gb,
                bandwidth_gb_s = gpu.spec.bandwidth_gb_s,
                price_1x = price_1,
                price_8x = price_8,
                efficiency = efficiency,
                "GPU pricing"
            );
        }
    }
}

impl Default for GpuDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof pricing calculator using the GPU database
pub struct ProofPricingCalculator {
    db: GpuDatabase,
    /// Margin percentage (e.g., 0.2 = 20% margin)
    margin: f64,
    /// Network overhead multiplier
    network_overhead: f64,
}

impl ProofPricingCalculator {
    pub fn new(margin: f64) -> Self {
        Self {
            db: GpuDatabase::new(),
            margin,
            network_overhead: 1.1, // 10% network overhead
        }
    }

    /// Calculate the cost to generate a single proof
    /// 
    /// # Arguments
    /// * `gpu_model` - The GPU model to use
    /// * `log_size` - Log2 of the polynomial size
    /// * `gpu_count` - Number of GPUs to use
    /// 
    /// # Returns
    /// Price in USD for a single proof, or None if GPU not found
    pub fn calculate_proof_cost(
        &self,
        gpu_model: &str,
        log_size: u32,
        gpu_count: u32,
    ) -> Option<ProofCostEstimate> {
        let gpu = self.db.get(gpu_model)?;
        let market_price = gpu.cheapest_price(gpu_count)?;

        // Estimate proof generation time based on benchmarks
        // These are rough estimates based on H100 benchmarks, scaled by bandwidth
        let h100_baseline_ms = match log_size {
            16 => 2.5,
            18 => 5.8,
            20 => 12.0,
            22 => 35.0,
            24 => 120.0,
            26 => 480.0,
            28 => 1920.0,
            _ => {
                // Interpolate/extrapolate
                let base = 2.5;
                base * (1u64 << (log_size.saturating_sub(16))) as f64 / 4.0
            }
        };

        // Scale by bandwidth ratio (H100 SXM has 3350 GB/s)
        let bandwidth_ratio = 3350.0 / gpu.spec.bandwidth_gb_s as f64;
        let estimated_time_ms = h100_baseline_ms * bandwidth_ratio;

        // Multi-GPU scaling (not perfect linear)
        let scaling_efficiency = match gpu_count {
            1 => 1.0,
            2 => 0.85, // 85% efficiency
            4 => 0.75, // 75% efficiency
            8 => 0.65, // 65% efficiency
            _ => 0.5,
        };
        let scaled_time_ms = estimated_time_ms / (gpu_count as f64 * scaling_efficiency);

        // Calculate cost
        let hours = scaled_time_ms / (1000.0 * 3600.0);
        let base_cost = market_price.price_per_hour * hours;
        let cost_with_overhead = base_cost * self.network_overhead;
        let final_cost = cost_with_overhead * (1.0 + self.margin);

        Some(ProofCostEstimate {
            gpu_model: gpu_model.to_string(),
            gpu_count,
            log_size,
            estimated_time_ms: scaled_time_ms,
            base_cost_usd: base_cost,
            final_cost_usd: final_cost,
            throughput_proofs_per_hour: 3600000.0 / scaled_time_ms,
            cost_per_million_proofs_usd: final_cost * 1_000_000.0,
        })
    }

    /// Find the most cost-effective GPU configuration for a workload
    pub fn find_optimal_config(
        &self,
        log_size: u32,
        proofs_needed: u64,
        deadline_hours: f64,
    ) -> Vec<ProofCostEstimate> {
        let mut results = Vec::new();

        for gpu in self.db.all() {
            for gpu_count in [1, 2, 4, 8] {
                if let Some(estimate) = self.calculate_proof_cost(&gpu.spec.model, log_size, gpu_count) {
                    // Check if configuration can meet deadline
                    let hours_needed = proofs_needed as f64 / estimate.throughput_proofs_per_hour;
                    if hours_needed <= deadline_hours {
                        results.push(estimate);
                    }
                }
            }
        }

        // Sort by cost per million proofs
        results.sort_by(|a, b| {
            a.cost_per_million_proofs_usd.partial_cmp(&b.cost_per_million_proofs_usd).unwrap()
        });

        results
    }

    /// Get the database reference
    pub fn database(&self) -> &GpuDatabase {
        &self.db
    }
}

/// Detailed proof cost estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCostEstimate {
    pub gpu_model: String,
    pub gpu_count: u32,
    pub log_size: u32,
    pub estimated_time_ms: f64,
    pub base_cost_usd: f64,
    pub final_cost_usd: f64,
    pub throughput_proofs_per_hour: f64,
    pub cost_per_million_proofs_usd: f64,
}

impl std::fmt::Display for ProofCostEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}x): {:.2}ms/proof, ${:.8}/proof, {:.0} proofs/hr, ${:.2}/M proofs",
            self.gpu_model,
            self.gpu_count,
            self.estimated_time_ms,
            self.final_cost_usd,
            self.throughput_proofs_per_hour,
            self.cost_per_million_proofs_usd,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_database_creation() {
        let db = GpuDatabase::new();
        assert!(db.count() > 20, "Should have at least 20 GPUs");
    }

    #[test]
    fn test_h100_pricing() {
        let db = GpuDatabase::new();
        let h100 = db.get("H100 SXM").expect("H100 SXM should exist");
        
        let cheapest_1x = h100.cheapest_price(1).expect("Should have 1x pricing");
        assert!(cheapest_1x.price_per_hour < 5.0, "H100 1x should be under $5/hr");
        
        let cheapest_8x = h100.cheapest_price(8).expect("Should have 8x pricing");
        assert!(cheapest_8x.price_per_hour < 30.0, "H100 8x should be under $30/hr");
    }

    #[test]
    fn test_blackwell_exists() {
        let db = GpuDatabase::new();
        assert!(db.get("B200").is_some(), "B200 should exist");
        assert!(db.get("B300").is_some(), "B300 should exist");
    }

    #[test]
    fn test_bandwidth_efficiency() {
        let db = GpuDatabase::new();
        let efficient = db.by_bandwidth_efficiency(1);
        assert!(!efficient.is_empty(), "Should have GPUs with efficiency data");
    }

    #[test]
    fn test_proof_cost_calculator() {
        let calc = ProofPricingCalculator::new(0.2);
        
        let estimate = calc.calculate_proof_cost("H100 SXM", 20, 1)
            .expect("Should calculate H100 proof cost");
        
        assert!(estimate.estimated_time_ms > 0.0);
        assert!(estimate.final_cost_usd > 0.0);
        assert!(estimate.throughput_proofs_per_hour > 0.0);
    }

    #[test]
    fn test_find_optimal_config() {
        let calc = ProofPricingCalculator::new(0.2);
        
        let configs = calc.find_optimal_config(20, 100_000, 1.0);
        assert!(!configs.is_empty(), "Should find at least one config");
        
        // First should be cheapest per proof
        let first = &configs[0];
        for config in &configs[1..] {
            assert!(
                first.cost_per_million_proofs_usd <= config.cost_per_million_proofs_usd,
                "Results should be sorted by cost"
            );
        }
    }
}
