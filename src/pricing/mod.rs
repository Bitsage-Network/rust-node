//! GPU Hourly Pricing Module
//!
//! Simple, transparent fixed hourly pricing for GPU compute.
//! Proof generation costs are bundled into the hourly rate with a markup.
//!
//! # Pricing Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                    SIMPLE FIXED PRICING                                     │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │   Customer pays:  GPU Hourly Rate + BitSage Markup                          │
//! │                                                                              │
//! │   Example: H100 SXM                                                          │
//! │   ├── Provider cost:     $2.39/hr                                           │
//! │   ├── BitSage markup:    +20%                                               │
//! │   ├── Proof generation:  (included)                                         │
//! │   └── Customer pays:     $2.87/hr                                           │
//! │                                                                              │
//! │   ZK proof costs are negligible and bundled into the hourly rate.           │
//! │   No separate charges. No surge pricing. Simple and transparent.            │
//! │                                                                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported GPUs (30+)
//!
//! | Generation | Models |
//! |------------|--------|
//! | Blackwell  | B300, B200, RTX Pro 6000, RTX 5090 |
//! | Hopper     | H200, H100 SXM, H100 PCIe |
//! | Ada        | L40S, L40, L4, RTX 6000 Ada, RTX 4090 |
//! | Ampere     | A100 (40/80GB), A40, A30, A10, A10G, A16, A6000, A5000, A4000 |
//! | Turing     | T4 |
//! | Volta      | V100 SXM2, V100 PCIe |
//! | Pascal     | P4 |
//! | Maxwell    | M60 |
//!
//! # Multi-GPU Configurations
//!
//! Pricing includes 1x, 2x, 4x, 8x, and 16x configurations from multiple providers.

pub mod gpu_database;
pub mod market_state;

// Comprehensive GPU database with real market pricing
pub use gpu_database::{
    GpuDatabase, GpuFullSpec, GpuWithPricing, MarketPrice,
    GpuArchitecture, FormFactor, ProofPricingCalculator, ProofCostEstimate,
};

// Market state tracking (for provider registry, not dynamic pricing)
pub use market_state::{
    MarketState, WorkerPool,
};
