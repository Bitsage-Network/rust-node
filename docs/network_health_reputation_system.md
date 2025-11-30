# Network Health and Reputation System

## Overview

The Network Health and Reputation System is a comprehensive solution that provides:

1. **Worker Performance Tracking** - Monitor individual worker performance metrics
2. **Dynamic Reputation Scoring** - Calculate and update reputation scores based on performance
3. **Network Health Monitoring** - Track overall network health and status
4. **Reputation-based Worker Selection** - Use reputation and health scores for job assignment
5. **Penalty Mechanisms** - Enforce penalties for bad behavior and failures

## Architecture

### Core Components

#### 1. HealthReputationSystem
The main orchestrator that manages:
- Worker health monitoring
- Reputation tracking
- Penalty enforcement
- Network health aggregation

#### 2. WorkerHealth
Tracks real-time health metrics for each worker:
- CPU, memory, and disk usage
- Network latency and bandwidth
- GPU utilization and temperature
- Response times and error counts
- Overall health score calculation

#### 3. WorkerReputation
Comprehensive reputation tracking including:
- Job success/failure rates
- Performance metrics (completion time, quality)
- Penalty history
- Ban status and reasons
- Reputation decay over time

#### 4. NetworkHealth
Aggregated network-wide metrics:
- Total, active, and healthy worker counts
- Average reputation scores
- Success rates and response times
- Overall network health score

## Key Features

### 1. Worker Performance Tracking

```rust
// Update worker health metrics
health_system.update_worker_health(worker_id, metrics).await?;

// Health metrics include:
struct HealthMetrics {
    response_time_ms: u64,
    cpu_usage_percent: f32,
    memory_usage_percent: f32,
    disk_usage_percent: f32,
    network_latency_ms: u64,
    temperature_celsius: Option<f32>,
    gpu_utilization_percent: Option<f32>,
    // ... more metrics
}
```

### 2. Dynamic Reputation Scoring

The system calculates reputation scores based on multiple factors:

- **Success Rate** (40% weight) - Ratio of completed vs failed jobs
- **Reliability Score** (25% weight) - Consistency in performance
- **Efficiency Score** (20% weight) - Resource usage optimization
- **Consistency Score** (15% weight) - Predictable behavior

```rust
// Update reputation after job completion
health_system.update_worker_reputation(
    worker_id,
    success: bool,
    execution_time_ms: u64,
    earnings: u128,
    result_quality: Option<f64>,
).await?;
```

### 3. Network Health Monitoring

Real-time monitoring of network-wide metrics:

```rust
let network_health = health_system.get_network_health().await;
println!("Network Health Score: {:.2}", network_health.health_score);
println!("Active Workers: {}/{}", network_health.active_workers, network_health.total_workers);
println!("Average Reputation: {:.2}", network_health.average_reputation);
```

### 4. Reputation-based Worker Selection

Enhanced job distribution that considers both reputation and health:

```rust
// Worker selection score calculation
fn calculate_worker_score(&self, bid: &WorkerBid) -> f64 {
    let reputation_score = bid.reputation_score * 0.35;
    let health_score = bid.health_score * 0.25;
    let bid_score = (1.0 / (bid.bid_amount as f64 + 1.0)) * 0.25;
    let time_score = (1.0 / (bid.estimated_completion_time as f64 + 1.0)) * 0.15;
    
    reputation_score + health_score + bid_score + time_score
}
```

### 5. Penalty Mechanisms

Comprehensive penalty system for various violations:

```rust
// Apply penalties for different types of violations
health_system.apply_penalty(
    worker_id,
    PenaltyType::JobTimeout,
    0.3, // severity
    "Job timeout".to_string(),
    Some(job_id),
).await?;

// Penalty types include:
enum PenaltyType {
    JobTimeout,
    JobFailure,
    MaliciousBehavior,
    PoorPerformance,
    NetworkIssues,
    ResourceAbuse,
    InvalidResult,
    Spam,
    Ban,
}
```

### 6. Malicious Behavior Detection

Advanced detection and handling of malicious activities:

```rust
// Detect and handle malicious behavior
health_system.detect_malicious_behavior(
    worker_id,
    "Invalid result submission".to_string(),
).await?;

// Automatic banning for repeated violations
if reputation.malicious_behavior_count >= 3 {
    health_system.ban_worker(&worker_id, "Repeated malicious behavior").await?;
}
```

## Configuration

The system is highly configurable through `HealthReputationConfig`:

```rust
let config = HealthReputationConfig {
    health_check_interval_secs: 60,
    reputation_decay_rate: 0.01, // 1% decay per day
    min_reputation_threshold: 0.3,
    max_reputation_score: 1.0,
    failure_penalty_multiplier: 0.9,
    success_bonus_multiplier: 1.05,
    timeout_penalty_severity: 0.8,
    malicious_penalty_severity: 0.5,
    enable_auto_ban: true,
    // ... more configuration options
};
```

## Integration with Job Distribution

The health and reputation system is seamlessly integrated with the job distribution system:

```rust
// Job distributor with health reputation system
let job_distributor = JobDistributor::new(
    job_config,
    blockchain_client,
    job_manager,
    p2p_network,
);

// Access health reputation system
let health_system = job_distributor.health_reputation_system();

// Check worker eligibility before job assignment
if health_system.is_worker_eligible(&worker_id).await {
    // Assign job to worker
}
```

## Usage Examples

### Basic Health Monitoring

```rust
// Update worker health
let metrics = HealthMetrics {
    response_time_ms: 150,
    cpu_usage_percent: 65.0,
    memory_usage_percent: 70.0,
    // ... other metrics
};

health_system.update_worker_health(worker_id, metrics).await?;

// Get worker health
if let Some(health) = health_system.get_worker_health(&worker_id).await {
    println!("Health Score: {:.2}", health.health_score);
}
```

### Reputation Management

```rust
// Update reputation after job completion
health_system.update_worker_reputation(
    worker_id,
    true, // success
    5000, // execution time
    100,  // earnings
    Some(0.95), // quality score
).await?;

// Get worker reputation
if let Some(reputation) = health_system.get_worker_reputation(&worker_id).await {
    println!("Reputation: {:.2}", reputation.reputation_score);
    println!("Jobs Completed: {}", reputation.jobs_completed);
}
```

### Penalty Enforcement

```rust
// Apply penalty for timeout
health_system.apply_penalty(
    worker_id,
    PenaltyType::JobTimeout,
    0.3,
    "Job timed out".to_string(),
    Some(job_id),
).await?;

// Check if worker is banned
if let Some(reputation) = health_system.get_worker_reputation(&worker_id).await {
    if reputation.is_banned {
        println!("Worker is banned: {}", reputation.ban_reason.unwrap());
    }
}
```

### Network Health Monitoring

```rust
// Get network health summary
let network_health = health_system.get_network_health().await;

println!("Network Status:");
println!("  Total Workers: {}", network_health.total_workers);
println!("  Active Workers: {}", network_health.active_workers);
println!("  Healthy Workers: {}", network_health.healthy_workers);
println!("  Banned Workers: {}", network_health.banned_workers);
println!("  Average Reputation: {:.2}", network_health.average_reputation);
println!("  Success Rate: {:.2}", network_health.success_rate);
println!("  Health Score: {:.2}", network_health.health_score);
```

## Testing

The system includes comprehensive tests:

```bash
# Run health reputation tests
cargo test health_reputation --lib

# Run integration tests
cargo test test_health_reputation_integration --lib

# Run the demo
cargo run --bin health_reputation_demo
```

## Benefits

1. **Improved Job Success Rates** - Better worker selection based on reputation and health
2. **Reduced Malicious Behavior** - Automatic detection and banning of bad actors
3. **Network Stability** - Real-time monitoring and health scoring
4. **Fair Resource Allocation** - Reputation-based job distribution
5. **Self-Healing Network** - Automatic reputation recovery and penalty enforcement

## Future Enhancements

1. **Machine Learning Integration** - Advanced reputation scoring using ML models
2. **Cross-Network Reputation** - Reputation portability across different networks
3. **Advanced Analytics** - Detailed performance analytics and insights
4. **Automated Remediation** - Self-healing mechanisms for network issues
5. **Reputation Marketplace** - Trading and selling of reputation scores

## Conclusion

The Network Health and Reputation System provides a robust foundation for maintaining a healthy, efficient, and secure distributed computing network. By combining real-time health monitoring with sophisticated reputation scoring, the system ensures optimal job distribution while protecting against malicious behavior and poor performance. 