//! # Cloud GPU Manager Demo
//!
//! Demonstrates launching and managing GPU instances across multiple cloud providers.

use bitsage_node::cloud::{CloudConfig, CloudGpuManager, ProviderType};
use bitsage_node::cloud::providers::MockCloudProvider;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🌩️ BitSage Cloud GPU Manager Demo");
    println!("===================================\n");

    // 1. Initialize cloud providers
    println!("📡 Step 1: Initializing Cloud Providers");
    let config = CloudConfig::default();
    
    let mut providers:HashMap<ProviderType, Box<dyn bitsage_node::cloud::CloudProvider>> = HashMap::new();
    providers.insert(ProviderType::Aws, Box::new(MockCloudProvider::new(ProviderType::Aws)));
    providers.insert(ProviderType::Azure, Box::new(MockCloudProvider::new(ProviderType::Azure)));
    providers.insert(ProviderType::Gcp, Box::new(MockCloudProvider::new(ProviderType::Gcp)));
    
    println!("   ✅ Configured 3 providers: AWS, Azure, GCP\n");

    // 2. Create GPU manager
    let manager = CloudGpuManager::new(config, providers);

    // 3. List available GPU types
    println!("📋 Step 2: Listing Available GPU Types");
    let available_gpus = manager.list_all_available_gpus().await?;
    for (provider, types) in available_gpus.iter() {
        println!("   {} GPUs: {:?}", provider, types);
    }
    println!();

    // 4. Launch best available GPU for enterprise workload
    println!("🚀 Step 3: Launching Enterprise GPU (H100, TEE Required)");
    let mut tags = HashMap::new();
    tags.insert("job_id".to_string(), "enterprise-ml-001".to_string());
    tags.insert("workload".to_string(), "confidential-training".to_string());
    
    let enterprise_instance = manager.launch_best_available_gpu(
        80,    // 80GB VRAM
        true,  // Requires Confidential Compute (H100)
        tags.clone(),
    ).await?;

    println!("   ✅ Launched: {} on {}", enterprise_instance.instance_id, enterprise_instance.provider);
    println!("      GPU: {} x {} ({}GB)", 
             enterprise_instance.gpu_count,
             enterprise_instance.gpu_spec.model,
             enterprise_instance.gpu_spec.memory_gb);
    println!("      Cost: ${:.2}/hour", enterprise_instance.hourly_cost_usd);
    println!("      TEE Support: {}", enterprise_instance.gpu_spec.supports_confidential_compute);
    println!();

    // 5. Launch consumer GPU for art generation
    println!("🎨 Step 4: Launching Consumer GPU (A100, No TEE Required)");
    tags.insert("job_id".to_string(), "art-generation-42".to_string());
    tags.insert("workload".to_string(), "stable-diffusion".to_string());
    
    let consumer_instance = manager.launch_best_available_gpu(
        40,    // 40GB VRAM sufficient
        false, // No TEE required for public art
        tags,
    ).await?;

    println!("   ✅ Launched: {} on {}", consumer_instance.instance_id, consumer_instance.provider);
    println!("      GPU: {} x {} ({}GB)", 
             consumer_instance.gpu_count,
             consumer_instance.gpu_spec.model,
             consumer_instance.gpu_spec.memory_gb);
    println!("      Cost: ${:.2}/hour", consumer_instance.hourly_cost_usd);
    println!();

    // 6. Check instance statuses
    println!("📊 Step 5: Monitoring Instance Status");
    let statuses = manager.get_all_instance_statuses().await?;
    for (id, status) in statuses.iter() {
        println!("   Instance {}: {:?}", id, status);
    }
    println!();

    // 7. Calculate total costs
    println!("💰 Step 6: Cost Analysis");
    let total_cost = manager.get_total_hourly_cost().await;
    println!("   Total Hourly Cost: ${:.2}/hour", total_cost);
    println!("   Daily Projection: ${:.2}/day", total_cost * 24.0);
    println!("   Monthly Projection: ${:.2}/month (30 days)", total_cost * 24.0 * 30.0);
    println!();

    // 8. Provider distribution
    println!("🌍 Step 7: Provider Distribution");
    let counts = manager.get_instance_count_by_provider().await;
    for (provider, count) in counts.iter() {
        println!("   {}: {} running instances", provider, count);
    }
    println!();

    // 9. Cleanup
    println!("🧹 Step 8: Terminating Instances");
    manager.terminate_instance(&enterprise_instance.instance_id).await?;
    manager.terminate_instance(&consumer_instance.instance_id).await?;
    println!("   ✅ All instances terminated");

    println!("\n🎉 Demo Complete: Cloud GPU Management Operational");
    Ok(())
}

