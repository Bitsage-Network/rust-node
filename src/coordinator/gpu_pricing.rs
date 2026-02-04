//! # GPU Pricing Configuration
//!
//! Market-based GPU pricing for BitSage Network.
//! Prices are in USD per GPU-hour, derived from market research (Jan 2025).
//!
//! Sources: Lambda Labs, Crusoe Cloud, Hyperstack, vast.ai, CoreWeave
//!
//! BitSage targets competitive pricing between spot (lowest) and on-demand (mid).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GPU pricing tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GpuTier {
    /// Consumer GPUs (RTX 30xx, 40xx, 50xx)
    Consumer,
    /// Professional workstation GPUs (A6000, RTX 6000)
    Professional,
    /// Datacenter GPUs (A100, L40S, A40)
    Datacenter,
    /// Enterprise/AI GPUs (H100, H200, B200)
    Enterprise,
    /// Frontier GPUs (GB200, MI300X)
    Frontier,
}

/// GPU model with pricing info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuModel {
    pub name: &'static str,
    pub vram_gb: u32,
    pub tier: GpuTier,
    /// Market low price (spot/vast.ai) in USD cents per hour
    pub price_low_cents: u32,
    /// Market mid price (on-demand) in USD cents per hour
    pub price_mid_cents: u32,
    /// Market high price (reserved/premium) in USD cents per hour
    pub price_high_cents: u32,
    /// BitSage network rate in USD cents per hour (competitive mid-low)
    pub bitsage_rate_cents: u32,
}

/// Get all supported GPU models with pricing
pub fn get_gpu_pricing() -> HashMap<&'static str, GpuModel> {
    let mut gpus = HashMap::new();

    // =========================================================================
    // FRONTIER TIER - Next-gen AI accelerators
    // =========================================================================
    gpus.insert("GB200", GpuModel {
        name: "NVIDIA GB200 NVL72",
        vram_gb: 186,
        tier: GpuTier::Frontier,
        price_low_cents: 0,      // Not available spot
        price_mid_cents: 0,      // Contact sales
        price_high_cents: 0,
        bitsage_rate_cents: 500, // $5.00/hr (premium, limited supply)
    });

    gpus.insert("B200", GpuModel {
        name: "NVIDIA B200 SXM",
        vram_gb: 180,
        tier: GpuTier::Frontier,
        price_low_cents: 244,    // vast.ai $2.44
        price_mid_cents: 499,    // Lambda $4.99
        price_high_cents: 529,   // Lambda 1x $5.29
        bitsage_rate_cents: 350, // $3.50/hr
    });

    gpus.insert("MI300X", GpuModel {
        name: "AMD MI300X",
        vram_gb: 192,
        tier: GpuTier::Frontier,
        price_low_cents: 95,     // Crusoe spot $0.95
        price_mid_cents: 345,    // Crusoe on-demand $3.45
        price_high_cents: 400,
        bitsage_rate_cents: 200, // $2.00/hr (AMD discount)
    });

    // =========================================================================
    // ENTERPRISE TIER - H100/H200 family
    // =========================================================================
    gpus.insert("H200_SXM", GpuModel {
        name: "NVIDIA H200 SXM",
        vram_gb: 141,
        tier: GpuTier::Enterprise,
        price_low_cents: 219,    // vast.ai $2.19
        price_mid_cents: 350,    // Hyperstack $3.50
        price_high_cents: 429,   // Crusoe $4.29
        bitsage_rate_cents: 280, // $2.80/hr
    });

    gpus.insert("H200_NVL", GpuModel {
        name: "NVIDIA H200 NVLink",
        vram_gb: 141,
        tier: GpuTier::Enterprise,
        price_low_cents: 180,    // vast.ai $1.80
        price_mid_cents: 350,
        price_high_cents: 429,
        bitsage_rate_cents: 250, // $2.50/hr
    });

    gpus.insert("H100_SXM", GpuModel {
        name: "NVIDIA H100 SXM",
        vram_gb: 80,
        tier: GpuTier::Enterprise,
        price_low_cents: 156,    // vast.ai $1.56
        price_mid_cents: 240,    // Hyperstack $2.40
        price_high_cents: 390,   // Crusoe $3.90
        bitsage_rate_cents: 200, // $2.00/hr
    });

    gpus.insert("H100_NVL", GpuModel {
        name: "NVIDIA H100 NVLink",
        vram_gb: 80,
        tier: GpuTier::Enterprise,
        price_low_cents: 187,    // vast.ai $1.87
        price_mid_cents: 195,    // Hyperstack $1.95
        price_high_cents: 253,   // Brev $2.53
        bitsage_rate_cents: 180, // $1.80/hr
    });

    gpus.insert("H100_PCIe", GpuModel {
        name: "NVIDIA H100 PCIe",
        vram_gb: 80,
        tier: GpuTier::Enterprise,
        price_low_cents: 152,    // Hyperstack spot $1.52
        price_mid_cents: 190,    // Hyperstack $1.90
        price_high_cents: 249,   // Lambda $2.49
        bitsage_rate_cents: 170, // $1.70/hr
    });

    gpus.insert("GH200", GpuModel {
        name: "NVIDIA GH200 Grace Hopper",
        vram_gb: 96,
        tier: GpuTier::Enterprise,
        price_low_cents: 149,    // Lambda $1.49
        price_mid_cents: 200,
        price_high_cents: 250,
        bitsage_rate_cents: 160, // $1.60/hr
    });

    // =========================================================================
    // DATACENTER TIER - A100, L40S, A40
    // =========================================================================
    gpus.insert("A100_SXM_80GB", GpuModel {
        name: "NVIDIA A100 SXM 80GB",
        vram_gb: 80,
        tier: GpuTier::Datacenter,
        price_low_cents: 61,     // vast.ai $0.61
        price_mid_cents: 160,    // Hyperstack $1.60
        price_high_cents: 195,   // Crusoe $1.95
        bitsage_rate_cents: 120, // $1.20/hr
    });

    gpus.insert("A100_PCIe_80GB", GpuModel {
        name: "NVIDIA A100 PCIe 80GB",
        vram_gb: 80,
        tier: GpuTier::Datacenter,
        price_low_cents: 52,     // vast.ai $0.52
        price_mid_cents: 120,    // Brev $1.20
        price_high_cents: 165,   // Crusoe $1.65
        bitsage_rate_cents: 100, // $1.00/hr
    });

    gpus.insert("A100_PCIe_40GB", GpuModel {
        name: "NVIDIA A100 PCIe 40GB",
        vram_gb: 40,
        tier: GpuTier::Datacenter,
        price_low_cents: 100,    // Crusoe spot $1.00
        price_mid_cents: 129,    // Lambda $1.29
        price_high_cents: 145,   // Crusoe $1.45
        bitsage_rate_cents: 80,  // $0.80/hr
    });

    gpus.insert("L40S", GpuModel {
        name: "NVIDIA L40S",
        vram_gb: 48,
        tier: GpuTier::Datacenter,
        price_low_cents: 47,     // vast.ai $0.47
        price_mid_cents: 86,     // Brev $0.86
        price_high_cents: 100,   // Crusoe $1.00
        bitsage_rate_cents: 70,  // $0.70/hr
    });

    gpus.insert("L40", GpuModel {
        name: "NVIDIA L40",
        vram_gb: 48,
        tier: GpuTier::Datacenter,
        price_low_cents: 80,     // Hyperstack spot $0.80
        price_mid_cents: 95,     // Brev $0.95
        price_high_cents: 100,   // Hyperstack $1.00
        bitsage_rate_cents: 75,  // $0.75/hr
    });

    gpus.insert("A40", GpuModel {
        name: "NVIDIA A40",
        vram_gb: 48,
        tier: GpuTier::Datacenter,
        price_low_cents: 39,     // vast.ai $0.39
        price_mid_cents: 51,     // Brev $0.51
        price_high_cents: 90,    // Crusoe $0.90
        bitsage_rate_cents: 45,  // $0.45/hr
    });

    gpus.insert("A30", GpuModel {
        name: "NVIDIA A30",
        vram_gb: 24,
        tier: GpuTier::Datacenter,
        price_low_cents: 25,     // Brev $0.25
        price_mid_cents: 40,
        price_high_cents: 50,
        bitsage_rate_cents: 30,  // $0.30/hr
    });

    gpus.insert("A10", GpuModel {
        name: "NVIDIA A10",
        vram_gb: 24,
        tier: GpuTier::Datacenter,
        price_low_cents: 50,
        price_mid_cents: 75,     // Lambda $0.75
        price_high_cents: 100,
        bitsage_rate_cents: 55,  // $0.55/hr
    });

    // =========================================================================
    // PROFESSIONAL TIER - Workstation GPUs
    // =========================================================================
    gpus.insert("RTX_6000_ADA", GpuModel {
        name: "NVIDIA RTX 6000 Ada",
        vram_gb: 48,
        tier: GpuTier::Professional,
        price_low_cents: 47,     // vast.ai $0.47
        price_mid_cents: 75,     // Brev $0.75
        price_high_cents: 180,   // Hyperstack $1.80
        bitsage_rate_cents: 60,  // $0.60/hr
    });

    gpus.insert("RTX_PRO_6000", GpuModel {
        name: "NVIDIA RTX PRO 6000",
        vram_gb: 96,
        tier: GpuTier::Professional,
        price_low_cents: 79,     // vast.ai $0.79
        price_mid_cents: 91,     // vast.ai $0.91
        price_high_cents: 180,   // Hyperstack $1.80
        bitsage_rate_cents: 85,  // $0.85/hr
    });

    gpus.insert("RTX_A6000", GpuModel {
        name: "NVIDIA RTX A6000",
        vram_gb: 48,
        tier: GpuTier::Professional,
        price_low_cents: 37,     // vast.ai $0.37
        price_mid_cents: 50,     // Hyperstack $0.50
        price_high_cents: 80,    // Lambda $0.80
        bitsage_rate_cents: 40,  // $0.40/hr
    });

    gpus.insert("RTX_A5000", GpuModel {
        name: "NVIDIA RTX A5000",
        vram_gb: 24,
        tier: GpuTier::Professional,
        price_low_cents: 17,     // vast.ai $0.17
        price_mid_cents: 41,     // Brev $0.41
        price_high_cents: 50,
        bitsage_rate_cents: 25,  // $0.25/hr
    });

    gpus.insert("RTX_A4000", GpuModel {
        name: "NVIDIA RTX A4000",
        vram_gb: 16,
        tier: GpuTier::Professional,
        price_low_cents: 7,      // vast.ai $0.07
        price_mid_cents: 15,     // Hyperstack $0.15
        price_high_cents: 25,
        bitsage_rate_cents: 10,  // $0.10/hr
    });

    gpus.insert("QUADRO_RTX_8000", GpuModel {
        name: "NVIDIA Quadro RTX 8000",
        vram_gb: 48,
        tier: GpuTier::Professional,
        price_low_cents: 24,     // vast.ai $0.24
        price_mid_cents: 40,
        price_high_cents: 60,
        bitsage_rate_cents: 30,  // $0.30/hr
    });

    gpus.insert("QUADRO_RTX_6000", GpuModel {
        name: "NVIDIA Quadro RTX 6000",
        vram_gb: 24,
        tier: GpuTier::Professional,
        price_low_cents: 50,     // Lambda $0.50
        price_mid_cents: 60,
        price_high_cents: 80,
        bitsage_rate_cents: 35,  // $0.35/hr
    });

    // =========================================================================
    // CONSUMER TIER - Gaming GPUs
    // =========================================================================
    gpus.insert("RTX_5090", GpuModel {
        name: "NVIDIA RTX 5090",
        vram_gb: 32,
        tier: GpuTier::Consumer,
        price_low_cents: 35,     // vast.ai $0.35
        price_mid_cents: 50,
        price_high_cents: 80,
        bitsage_rate_cents: 40,  // $0.40/hr
    });

    gpus.insert("RTX_5080", GpuModel {
        name: "NVIDIA RTX 5080",
        vram_gb: 16,
        tier: GpuTier::Consumer,
        price_low_cents: 12,     // vast.ai $0.12
        price_mid_cents: 25,
        price_high_cents: 40,
        bitsage_rate_cents: 18,  // $0.18/hr
    });

    gpus.insert("RTX_5070_Ti", GpuModel {
        name: "NVIDIA RTX 5070 Ti",
        vram_gb: 16,
        tier: GpuTier::Consumer,
        price_low_cents: 10,     // vast.ai $0.10
        price_mid_cents: 20,
        price_high_cents: 35,
        bitsage_rate_cents: 14,  // $0.14/hr
    });

    gpus.insert("RTX_4090", GpuModel {
        name: "NVIDIA RTX 4090",
        vram_gb: 24,
        tier: GpuTier::Consumer,
        price_low_cents: 29,     // vast.ai $0.29
        price_mid_cents: 45,
        price_high_cents: 60,
        bitsage_rate_cents: 35,  // $0.35/hr
    });

    gpus.insert("RTX_4080_Super", GpuModel {
        name: "NVIDIA RTX 4080 Super",
        vram_gb: 16,
        tier: GpuTier::Consumer,
        price_low_cents: 15,     // vast.ai $0.15
        price_mid_cents: 25,
        price_high_cents: 40,
        bitsage_rate_cents: 18,  // $0.18/hr
    });

    gpus.insert("RTX_4080", GpuModel {
        name: "NVIDIA RTX 4080",
        vram_gb: 16,
        tier: GpuTier::Consumer,
        price_low_cents: 13,     // vast.ai $0.13
        price_mid_cents: 22,
        price_high_cents: 35,
        bitsage_rate_cents: 16,  // $0.16/hr
    });

    gpus.insert("RTX_4070_Ti_Super", GpuModel {
        name: "NVIDIA RTX 4070 Ti Super",
        vram_gb: 16,
        tier: GpuTier::Consumer,
        price_low_cents: 13,     // vast.ai $0.13
        price_mid_cents: 20,
        price_high_cents: 30,
        bitsage_rate_cents: 15,  // $0.15/hr
    });

    gpus.insert("RTX_4070_Ti", GpuModel {
        name: "NVIDIA RTX 4070 Ti",
        vram_gb: 12,
        tier: GpuTier::Consumer,
        price_low_cents: 8,      // vast.ai $0.08
        price_mid_cents: 15,
        price_high_cents: 25,
        bitsage_rate_cents: 10,  // $0.10/hr
    });

    gpus.insert("RTX_4070_Super", GpuModel {
        name: "NVIDIA RTX 4070 Super",
        vram_gb: 12,
        tier: GpuTier::Consumer,
        price_low_cents: 8,      // vast.ai $0.08
        price_mid_cents: 14,
        price_high_cents: 22,
        bitsage_rate_cents: 10,  // $0.10/hr
    });

    gpus.insert("RTX_4070", GpuModel {
        name: "NVIDIA RTX 4070",
        vram_gb: 12,
        tier: GpuTier::Consumer,
        price_low_cents: 7,      // vast.ai $0.07
        price_mid_cents: 12,
        price_high_cents: 20,
        bitsage_rate_cents: 9,   // $0.09/hr
    });

    gpus.insert("RTX_4060_Ti", GpuModel {
        name: "NVIDIA RTX 4060 Ti",
        vram_gb: 16,
        tier: GpuTier::Consumer,
        price_low_cents: 7,      // vast.ai $0.07
        price_mid_cents: 12,
        price_high_cents: 18,
        bitsage_rate_cents: 8,   // $0.08/hr
    });

    gpus.insert("RTX_3090", GpuModel {
        name: "NVIDIA RTX 3090",
        vram_gb: 24,
        tier: GpuTier::Consumer,
        price_low_cents: 12,     // vast.ai $0.12
        price_mid_cents: 25,
        price_high_cents: 40,
        bitsage_rate_cents: 18,  // $0.18/hr
    });

    gpus.insert("RTX_3090_Ti", GpuModel {
        name: "NVIDIA RTX 3090 Ti",
        vram_gb: 24,
        tier: GpuTier::Consumer,
        price_low_cents: 13,     // vast.ai $0.13
        price_mid_cents: 28,
        price_high_cents: 45,
        bitsage_rate_cents: 20,  // $0.20/hr
    });

    gpus.insert("RTX_3080_Ti", GpuModel {
        name: "NVIDIA RTX 3080 Ti",
        vram_gb: 12,
        tier: GpuTier::Consumer,
        price_low_cents: 8,      // vast.ai $0.08
        price_mid_cents: 15,
        price_high_cents: 25,
        bitsage_rate_cents: 10,  // $0.10/hr
    });

    gpus.insert("RTX_3080", GpuModel {
        name: "NVIDIA RTX 3080",
        vram_gb: 10,
        tier: GpuTier::Consumer,
        price_low_cents: 7,      // vast.ai $0.07
        price_mid_cents: 12,
        price_high_cents: 20,
        bitsage_rate_cents: 8,   // $0.08/hr
    });

    gpus.insert("RTX_3070_Ti", GpuModel {
        name: "NVIDIA RTX 3070 Ti",
        vram_gb: 8,
        tier: GpuTier::Consumer,
        price_low_cents: 5,      // vast.ai $0.05
        price_mid_cents: 10,
        price_high_cents: 18,
        bitsage_rate_cents: 7,   // $0.07/hr
    });

    gpus.insert("RTX_3070", GpuModel {
        name: "NVIDIA RTX 3070",
        vram_gb: 8,
        tier: GpuTier::Consumer,
        price_low_cents: 5,      // vast.ai $0.05
        price_mid_cents: 9,
        price_high_cents: 15,
        bitsage_rate_cents: 6,   // $0.06/hr
    });

    gpus.insert("RTX_3060", GpuModel {
        name: "NVIDIA RTX 3060",
        vram_gb: 12,
        tier: GpuTier::Consumer,
        price_low_cents: 5,      // vast.ai $0.05
        price_mid_cents: 8,
        price_high_cents: 14,
        bitsage_rate_cents: 6,   // $0.06/hr
    });

    // =========================================================================
    // LEGACY TIER - Older GPUs (still useful for some workloads)
    // =========================================================================
    gpus.insert("Tesla_V100", GpuModel {
        name: "NVIDIA Tesla V100",
        vram_gb: 16,
        tier: GpuTier::Datacenter,
        price_low_cents: 9,      // vast.ai $0.09
        price_mid_cents: 55,     // Lambda $0.55
        price_high_cents: 80,
        bitsage_rate_cents: 25,  // $0.25/hr
    });

    gpus.insert("RTX_2080_Ti", GpuModel {
        name: "NVIDIA RTX 2080 Ti",
        vram_gb: 11,
        tier: GpuTier::Consumer,
        price_low_cents: 6,      // vast.ai $0.06
        price_mid_cents: 10,
        price_high_cents: 18,
        bitsage_rate_cents: 7,   // $0.07/hr
    });

    gpus.insert("GTX_1080", GpuModel {
        name: "NVIDIA GTX 1080",
        vram_gb: 8,
        tier: GpuTier::Consumer,
        price_low_cents: 4,      // vast.ai $0.04
        price_mid_cents: 7,
        price_high_cents: 12,
        bitsage_rate_cents: 5,   // $0.05/hr
    });

    gpus

}

/// Get pricing for a specific GPU model
pub fn get_gpu_rate(_gpu_name: &str) -> Option<&'static GpuModel> {
    // Use lazy_static or similar in production
    // For now, this is a helper function
    None // TODO: implement with static storage
}

/// Calculate job cost based on GPU model and duration
pub fn calculate_job_cost(gpu_name: &str, duration_seconds: u64) -> Option<JobCost> {
    let gpus = get_gpu_pricing();
    let gpu = gpus.get(gpu_name)?;

    let hours = duration_seconds as f64 / 3600.0;
    let total_cents = (gpu.bitsage_rate_cents as f64 * hours) as u64;

    // Ensure minimum 1 cent
    let total_cents = std::cmp::max(total_cents, 1);

    // 80/20 split
    let worker_cents = total_cents * 80 / 100;
    let protocol_fee_cents = total_cents - worker_cents;

    // Protocol fee breakdown: 70% burn, 20% treasury, 10% stakers
    let burn_cents = protocol_fee_cents * 70 / 100;
    let treasury_cents = protocol_fee_cents * 20 / 100;
    let staker_cents = protocol_fee_cents - burn_cents - treasury_cents;

    Some(JobCost {
        gpu_name: gpu.name,
        duration_seconds,
        rate_cents_per_hour: gpu.bitsage_rate_cents,
        total_cents,
        worker_payment_cents: worker_cents,
        protocol_fee_cents,
        burn_cents,
        treasury_cents,
        staker_cents,
    })
}

/// Calculated job cost breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCost {
    pub gpu_name: &'static str,
    pub duration_seconds: u64,
    pub rate_cents_per_hour: u32,
    pub total_cents: u64,
    pub worker_payment_cents: u64,
    pub protocol_fee_cents: u64,
    pub burn_cents: u64,
    pub treasury_cents: u64,
    pub staker_cents: u64,
}

impl JobCost {
    /// Total cost in USD
    pub fn total_usd(&self) -> f64 {
        self.total_cents as f64 / 100.0
    }

    /// Worker payment in USD
    pub fn worker_usd(&self) -> f64 {
        self.worker_payment_cents as f64 / 100.0
    }
}

/// Summary of BitSage GPU pricing tiers
pub fn get_pricing_summary() -> serde_json::Value {
    serde_json::json!({
        "pricing_model": "market_competitive_usd",
        "fee_split": {
            "worker": "80%",
            "protocol": "20%",
            "protocol_breakdown": {
                "burn": "70% of protocol fee",
                "treasury": "20% of protocol fee",
                "stakers": "10% of protocol fee"
            }
        },
        "tiers": {
            "frontier": {
                "examples": ["GB200", "B200", "MI300X"],
                "price_range_usd": "$2.00 - $5.00/hr"
            },
            "enterprise": {
                "examples": ["H200", "H100", "GH200"],
                "price_range_usd": "$1.60 - $2.80/hr"
            },
            "datacenter": {
                "examples": ["A100", "L40S", "A40", "A10"],
                "price_range_usd": "$0.30 - $1.20/hr"
            },
            "professional": {
                "examples": ["RTX 6000 Ada", "RTX A6000", "RTX A5000"],
                "price_range_usd": "$0.10 - $0.85/hr"
            },
            "consumer": {
                "examples": ["RTX 5090", "RTX 4090", "RTX 3090"],
                "price_range_usd": "$0.05 - $0.40/hr"
            }
        },
        "competitive_position": "Below mid-market, above spot pricing",
        "payment_tokens": ["SAGE", "USDC", "STRK"],
        "sage_discount": "20% discount when paying in SAGE"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pricing_loaded() {
        let gpus = get_gpu_pricing();
        assert!(gpus.len() > 30, "Should have 30+ GPU models");
        assert!(gpus.contains_key("RTX_4090"));
        assert!(gpus.contains_key("H100_SXM"));
        assert!(gpus.contains_key("A100_PCIe_80GB"));
    }

    #[test]
    fn test_price_ordering() {
        let gpus = get_gpu_pricing();

        // H100 should cost more than A100
        let h100 = gpus.get("H100_SXM").unwrap();
        let a100 = gpus.get("A100_SXM_80GB").unwrap();
        assert!(h100.bitsage_rate_cents > a100.bitsage_rate_cents);

        // A100 should cost more than RTX 4090
        let rtx4090 = gpus.get("RTX_4090").unwrap();
        assert!(a100.bitsage_rate_cents > rtx4090.bitsage_rate_cents);
    }
}
