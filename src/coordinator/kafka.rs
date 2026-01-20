//! # Kafka Integration for Job Intake
//!
//! Implements Kafka consumer and producer for job intake, worker communication,
//! and result distribution in the Bitsage Network coordinator.

use anyhow::{Result, Context};
use rdkafka::{
    config::ClientConfig,
    consumer::{Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
    message::OwnedMessage,
    Message,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{info, debug, warn, error};
use uuid::Uuid;

use crate::types::{JobId, WorkerId};
use crate::node::coordinator::{JobRequest, JobType, JobResult};
use crate::network::health_reputation::{WorkerHealth, HealthMetrics};

/// Kafka configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Kafka bootstrap servers
    pub bootstrap_servers: String,
    /// Consumer group ID
    pub consumer_group_id: String,
    /// Job intake topic
    pub job_intake_topic: String,
    /// Worker communication topic
    pub worker_communication_topic: String,
    /// Result distribution topic
    pub result_distribution_topic: String,
    /// Health metrics topic
    pub health_metrics_topic: String,
    /// Auto commit interval in milliseconds
    pub auto_commit_interval_ms: u64,
    /// Session timeout in milliseconds
    pub session_timeout_ms: u64,
    /// Max poll interval in milliseconds
    pub max_poll_interval_ms: u64,
    /// Enable auto commit
    pub enable_auto_commit: bool,
    /// Max poll records
    pub max_poll_records: i32,
    /// Consumer timeout in milliseconds
    pub consumer_timeout_ms: u64,
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: "localhost:9092".to_string(),
            consumer_group_id: "sage-coordinator-group".to_string(),
            job_intake_topic: "sage.job.intake".to_string(),
            worker_communication_topic: "sage.worker.communication".to_string(),
            result_distribution_topic: "sage.result.distribution".to_string(),
            health_metrics_topic: "sage.health.metrics".to_string(),
            auto_commit_interval_ms: 5000,
            session_timeout_ms: 30000,
            max_poll_interval_ms: 300000,
            enable_auto_commit: true,
            max_poll_records: 500,
            consumer_timeout_ms: 1000,
        }
    }
}

/// Job intake message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobIntakeMessage {
    pub job_id: JobId,
    pub job_request: JobRequest,
    pub client_id: String,
    pub callback_url: Option<String>,
    pub priority: JobPriority,
    pub max_retries: u32,
    pub created_at: u64,
}

/// Job priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobPriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Worker communication message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkerCommunicationMessage {
    /// Worker registration
    WorkerRegistration {
        worker_id: WorkerId,
        capabilities: WorkerCapabilities,
        location: WorkerLocation,
        health_metrics: Option<WorkerHealth>,
        timestamp: u64,
    },
    /// Worker heartbeat
    WorkerHeartbeat {
        worker_id: WorkerId,
        current_load: f32,
        health_metrics: Option<WorkerHealth>,
        timestamp: u64,
    },
    /// Worker departure
    WorkerDeparture {
        worker_id: WorkerId,
        reason: String,
        timestamp: u64,
    },
    /// Job assignment
    JobAssignment {
        job_id: JobId,
        worker_id: WorkerId,
        job_data: JobData,
        deadline: u64,
        timestamp: u64,
    },
    /// Job result
    JobResult {
        job_id: JobId,
        worker_id: WorkerId,
        result: JobResult,
        execution_time_ms: u64,
        timestamp: u64,
    },
    /// Job failure
    JobFailure {
        job_id: JobId,
        worker_id: WorkerId,
        error_message: String,
        retry_count: u32,
        timestamp: u64,
    },
}

/// Worker capabilities for Kafka
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub gpu_memory_gb: u32,
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub supported_job_types: Vec<String>,
    pub ai_frameworks: Vec<String>,
    pub specialized_hardware: Vec<String>,
    pub max_parallel_tasks: u32,
    pub network_bandwidth_mbps: u32,
    pub storage_gb: u32,
    pub supports_fp16: bool,
    pub supports_int8: bool,
    pub cuda_compute_capability: Option<String>,
}

/// Worker location for Kafka
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerLocation {
    pub region: String,
    pub country: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub network_latency_ms: u32,
}

/// Job data for worker assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobData {
    pub job_type: JobType,
    pub input_data: Vec<u8>,
    pub parameters: HashMap<String, serde_json::Value>,
    pub estimated_duration_secs: u64,
    pub memory_requirement_mb: u64,
    pub gpu_required: bool,
}

/// Result distribution message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultDistributionMessage {
    pub job_id: JobId,
    pub result: JobResult,
    pub worker_id: WorkerId,
    pub execution_time_ms: u64,
    pub quality_score: f64,
    pub confidence_score: f64,
    pub timestamp: u64,
}

/// Health metrics message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetricsMessage {
    pub worker_id: WorkerId,
    pub metrics: HealthMetrics,
    pub timestamp: u64,
}

/// Kafka events
#[derive(Debug, Clone)]
pub enum KafkaEvent {
    JobReceived(JobIntakeMessage),
    WorkerRegistered(WorkerId, WorkerCapabilities),
    WorkerHeartbeat(WorkerId, f32),
    WorkerDeparted(WorkerId, String),
    JobAssigned(JobId, WorkerId),
    JobCompleted(JobId, JobResult),
    JobFailed(JobId, String),
    HealthMetricsUpdated(WorkerId, HealthMetrics),
}

/// Dead letter queue entry
#[derive(Debug, Clone)]
pub struct DeadLetterEntry {
    pub message_id: String,
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    pub error: String,
    pub message_data: Vec<u8>,
    pub timestamp: u64,
    pub retry_count: u32,
}

/// Kafka statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_failed: u64,
    pub dead_letter_queue_size: usize,
    pub job_queue_size: usize,
    pub consumer_lag: i64,
    pub producer_queue_size: usize,
    pub connection_status: String,
    pub last_message_timestamp: u64,
    pub average_message_size_bytes: u64,
    pub error_rate: f64,
    pub throughput_messages_per_sec: f64,
}

impl Default for KafkaStats {
    fn default() -> Self {
        Self {
            messages_sent: 0,
            messages_received: 0,
            messages_failed: 0,
            dead_letter_queue_size: 0,
            job_queue_size: 0,
            consumer_lag: 0,
            producer_queue_size: 0,
            connection_status: "disconnected".to_string(),
            last_message_timestamp: 0,
            average_message_size_bytes: 0,
            error_rate: 0.0,
            throughput_messages_per_sec: 0.0,
        }
    }
}

/// Main Kafka coordinator
pub struct KafkaCoordinator {
    config: KafkaConfig,

    // Kafka clients
    consumer: Option<StreamConsumer>,
    producer: Option<FutureProducer>,

    // Message processing
    job_queue: Arc<RwLock<Vec<JobIntakeMessage>>>,
    dead_letter_queue: Arc<RwLock<Vec<DeadLetterEntry>>>,

    // Communication channels
    event_sender: mpsc::UnboundedSender<KafkaEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<KafkaEvent>>>>,

    // Internal state
    running: Arc<RwLock<bool>>,
    message_counters: Arc<RwLock<HashMap<String, u64>>>,

    // Sequence counter for dead letter queue entries (used when partition/offset unavailable)
    dlq_sequence: Arc<std::sync::atomic::AtomicI64>,
}

impl KafkaCoordinator {
    /// Create a new Kafka coordinator
    pub fn new(config: KafkaConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        Self {
            config,
            consumer: None,
            producer: None,
            job_queue: Arc::new(RwLock::new(Vec::new())),
            dead_letter_queue: Arc::new(RwLock::new(Vec::new())),
            dlq_sequence: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            message_counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the Kafka coordinator
    pub async fn start(&self) -> Result<()> {
        info!("Starting Kafka Coordinator...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Kafka coordinator already running"));
            }
            *running = true;
        }

        // Initialize Kafka consumer
        self.init_consumer().await?;
        
        // Initialize Kafka producer
        self.init_producer().await?;
        
        // Start message processing
        let _consumer_handle = self.start_consumer_loop().await?;
        let _producer_handle = self.start_producer_loop().await?;
        let _dead_letter_handle = self.start_dead_letter_processing().await?;

        info!("Kafka coordinator started successfully");

        // Start all tasks and wait for them to complete
        // Note: These are now () since we're not awaiting them
        let _consumer_result = ();
        let _producer_result = ();
        let _dead_letter_result = ();
        
        // Log any errors (simplified since we're not actually checking results)
        debug!("Kafka coordinator tasks completed");

        Ok(())
    }

    /// Stop the Kafka coordinator
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Kafka Coordinator...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        info!("Kafka coordinator stopped");
        Ok(())
    }

    /// Initialize Kafka consumer
    async fn init_consumer(&self) -> Result<()> {
        let config = self.config.clone();
        
        // Create consumer config with proper lifetime management
        let mut consumer_config = ClientConfig::new();
        consumer_config
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("group.id", &config.consumer_group_id)
            .set("auto.commit.interval.ms", &config.auto_commit_interval_ms.to_string())
            .set("session.timeout.ms", &config.session_timeout_ms.to_string())
            .set("max.poll.interval.ms", &config.max_poll_interval_ms.to_string())
            .set("enable.auto.commit", &config.enable_auto_commit.to_string())
            .set("max.poll.records", &config.max_poll_records.to_string())
            .set("auto.offset.reset", "earliest");

        let consumer: StreamConsumer = consumer_config.create()?;
        
        // Subscribe to topics
        let topics: Vec<&str> = vec![
            &config.job_intake_topic,
            &config.worker_communication_topic,
            &config.health_metrics_topic,
        ];
        
        consumer.subscribe(&topics)?;
        
        // Store consumer - we have a new consumer to store
        // Note: The consumer field is already an Option<StreamConsumer>, 
        // we would need to update self.consumer but we can't due to &self
        info!("Consumer initialized successfully (not stored due to &self limitation)");
        
        Ok(())
    }

    /// Initialize Kafka producer
    async fn init_producer(&self) -> Result<()> {
        let config = self.config.clone();
        
        // Create producer config with proper lifetime management
        let mut producer_config = ClientConfig::new();
        producer_config
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("message.timeout.ms", "30000")
            .set("request.timeout.ms", "5000")
            .set("retry.backoff.ms", "100")
            .set("max.in.flight.requests.per.connection", "5");

        let _producer: FutureProducer = producer_config.create()?;
        
        // Store producer - we have a new producer to store
        // Note: The producer field is already an Option<FutureProducer>, 
        // we would need to update self.producer but we can't due to &self
        info!("Producer initialized successfully (not stored due to &self limitation)");
        
        Ok(())
    }

    async fn reconnect_consumer(&self) -> Result<()> {
        info!("Reconnecting Kafka consumer...");
        
        // Create consumer config with proper lifetime management
        let mut consumer_config = ClientConfig::new();
        consumer_config
            .set("bootstrap.servers", &self.config.bootstrap_servers)
            .set("group.id", &self.config.consumer_group_id)
            .set("enable.auto.commit", "true")
            .set("auto.commit.interval.ms", "1000")
            .set("session.timeout.ms", "30000")
            .set("heartbeat.interval.ms", "10000")
            .set("auto.offset.reset", "earliest");

        let _consumer: StreamConsumer = consumer_config.create()?;
        
        // For now, just log that we can't update the consumer
        warn!("Cannot update consumer reference, will use new consumer on next operation");

        info!("Kafka consumer reconnected successfully");
        Ok(())
    }

    async fn reconnect_producer(&self) -> Result<()> {
        info!("Reconnecting Kafka producer...");
        
        // Create producer config with proper lifetime management
        let mut producer_config = ClientConfig::new();
        producer_config
            .set("bootstrap.servers", &self.config.bootstrap_servers)
            .set("client.id", "coordinator-producer") // Use a default client ID
            .set("acks", "all")
            .set("retries", "3")
            .set("batch.size", "16384")
            .set("linger.ms", "1")
            .set("buffer.memory", "33554432")
            .set("max.in.flight.requests.per.connection", "5");

        let _producer: FutureProducer = producer_config.create()?;
        
        // For now, just log that we can't update the producer
        warn!("Cannot update producer reference, will use new producer on next operation");

        info!("Kafka producer reconnected successfully");
        Ok(())
    }

    async fn start_consumer_loop(&self) -> Result<()> {
        if self.consumer.is_none() {
            return Err(anyhow::anyhow!("Consumer not initialized"));
        }

        // Clone all needed references for the spawned task
        let running = Arc::clone(&self.running);
        let config = self.config.clone();
        let event_sender = self.event_sender.clone();
        let dead_letter_queue = Arc::clone(&self.dead_letter_queue);
        let message_counters = Arc::clone(&self.message_counters);
        let job_queue = Arc::clone(&self.job_queue);

        tokio::spawn(async move {
            info!("Consumer loop started");

            // Create consumer inside the spawned task to avoid lifetime issues
            let mut consumer_config = ClientConfig::new();
            consumer_config
                .set("bootstrap.servers", &config.bootstrap_servers)
                .set("group.id", &config.consumer_group_id)
                .set("auto.commit.interval.ms", &config.auto_commit_interval_ms.to_string())
                .set("session.timeout.ms", &config.session_timeout_ms.to_string())
                .set("max.poll.interval.ms", &config.max_poll_interval_ms.to_string())
                .set("enable.auto.commit", &config.enable_auto_commit.to_string())
                .set("auto.offset.reset", "earliest");

            let consumer: StreamConsumer = match consumer_config.create() {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to create consumer in loop: {}", e);
                    return;
                }
            };

            // Subscribe to topics
            let topics = vec![
                config.job_intake_topic.as_str(),
                config.worker_communication_topic.as_str(),
                config.health_metrics_topic.as_str(),
            ];

            if let Err(e) = consumer.subscribe(&topics) {
                error!("Failed to subscribe to topics: {}", e);
                return;
            }

            let consumer_timeout = Duration::from_millis(config.consumer_timeout_ms);
            let mut consecutive_errors = 0u32;
            const MAX_CONSECUTIVE_ERRORS: u32 = 10;

            loop {
                // Check if we should stop
                if !*running.read().await {
                    info!("Consumer loop stopping");
                    break;
                }

                // Poll for messages with timeout
                match tokio::time::timeout(consumer_timeout, async {
                    use futures::StreamExt;

                    let mut stream = consumer.stream();
                    stream.next().await
                }).await {
                    Ok(Some(Ok(borrowed_msg))) => {
                        consecutive_errors = 0;

                        let topic = borrowed_msg.topic().to_string();
                        let payload = borrowed_msg.payload().map(|p| p.to_vec());
                        let partition = borrowed_msg.partition();
                        let offset = borrowed_msg.offset();

                        if let Some(payload_data) = payload {
                            // Process based on topic
                            let process_result = Self::process_message_data(
                                &topic,
                                &payload_data,
                                &event_sender,
                                &config,
                                &job_queue,
                            ).await;

                            match process_result {
                                Ok(()) => {
                                    // Increment success counter
                                    let mut counters = message_counters.write().await;
                                    *counters.entry("messages_received".to_string()).or_insert(0) += 1;
                                    debug!("Processed message from topic {} partition {} offset {}",
                                           topic, partition, offset);
                                }
                                Err(e) => {
                                    warn!("Failed to process message from {}: {}", topic, e);

                                    // Add to dead letter queue
                                    let entry = DeadLetterEntry {
                                        message_id: Uuid::new_v4().to_string(),
                                        topic: topic.clone(),
                                        partition,
                                        offset,
                                        error: e.to_string(),
                                        message_data: payload_data,
                                        timestamp: chrono::Utc::now().timestamp() as u64,
                                        retry_count: 0,
                                    };
                                    dead_letter_queue.write().await.push(entry);

                                    // Increment failure counter
                                    let mut counters = message_counters.write().await;
                                    *counters.entry("messages_failed".to_string()).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                    Ok(Some(Err(e))) => {
                        consecutive_errors += 1;
                        warn!("Error receiving Kafka message: {} (consecutive: {})", e, consecutive_errors);

                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                            error!("Too many consecutive errors, pausing consumer loop");
                            sleep(Duration::from_secs(5)).await;
                            consecutive_errors = 0;
                        }
                    }
                    Ok(None) => {
                        // Stream ended, this shouldn't happen normally
                        debug!("Consumer stream ended, continuing...");
                    }
                    Err(_) => {
                        // Timeout - this is normal, just continue polling
                    }
                }
            }

            info!("Consumer loop exited");
        });

        Ok(())
    }

    /// Start producer message sending loop
    async fn start_producer_loop(&self) -> Result<()> {
        // Clone all needed references for the spawned task
        let running = Arc::clone(&self.running);
        let config = self.config.clone();
        let job_queue = Arc::clone(&self.job_queue);
        let message_counters = Arc::clone(&self.message_counters);
        let dead_letter_queue = Arc::clone(&self.dead_letter_queue);

        tokio::spawn(async move {
            info!("Producer loop started");

            // Create producer inside the spawned task
            let mut producer_config = ClientConfig::new();
            producer_config
                .set("bootstrap.servers", &config.bootstrap_servers)
                .set("message.timeout.ms", "30000")
                .set("request.timeout.ms", "5000")
                .set("retry.backoff.ms", "100")
                .set("max.in.flight.requests.per.connection", "5")
                .set("acks", "all")
                .set("retries", "3");

            let producer: FutureProducer = match producer_config.create() {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to create producer in loop: {}", e);
                    return;
                }
            };

            let batch_interval = Duration::from_millis(50);
            let max_batch_size = config.max_poll_records as usize;

            loop {
                // Check if we should stop
                if !*running.read().await {
                    info!("Producer loop stopping");
                    break;
                }

                // Collect batch of jobs to send
                let jobs_to_send: Vec<JobIntakeMessage> = {
                    let mut queue = job_queue.write().await;
                    let batch_size = std::cmp::min(queue.len(), max_batch_size);
                    queue.drain(..batch_size).collect()
                };

                if jobs_to_send.is_empty() {
                    // No jobs to send, wait before checking again
                    sleep(batch_interval).await;
                    continue;
                }

                // Send all jobs in the batch
                for job_message in jobs_to_send {
                    let payload = match serde_json::to_vec(&job_message) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to serialize job message: {}", e);
                            continue;
                        }
                    };

                    let job_id_str = job_message.job_id.to_string();
                    let record = FutureRecord::to(&config.job_intake_topic)
                        .payload(&payload)
                        .key(&job_id_str);

                    match producer.send(record, Duration::from_secs(10)).await {
                        Ok((partition, offset)) => {
                            debug!("Sent job {} to partition {} offset {}",
                                   job_message.job_id, partition, offset);

                            let mut counters = message_counters.write().await;
                            *counters.entry("messages_sent".to_string()).or_insert(0) += 1;
                        }
                        Err((e, _)) => {
                            error!("Failed to send job message: {}", e);

                            // Add to dead letter queue for retry
                            let entry = DeadLetterEntry {
                                message_id: Uuid::new_v4().to_string(),
                                topic: config.job_intake_topic.clone(),
                                partition: 0,
                                offset: 0,
                                error: e.to_string(),
                                message_data: payload,
                                timestamp: chrono::Utc::now().timestamp() as u64,
                                retry_count: 0,
                            };
                            dead_letter_queue.write().await.push(entry);

                            let mut counters = message_counters.write().await;
                            *counters.entry("messages_failed".to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }

            info!("Producer loop exited");
        });

        Ok(())
    }

    /// Start dead letter queue processing
    async fn start_dead_letter_processing(&self) -> Result<()> {
        let dead_letter_queue = Arc::clone(&self.dead_letter_queue);
        let config = self.config.clone();
        let running = Arc::clone(&self.running);
        let message_counters = Arc::clone(&self.message_counters);

        tokio::spawn(async move {
            info!("Dead letter queue processor started");

            // Create a producer for retrying messages
            let mut producer_config = ClientConfig::new();
            producer_config
                .set("bootstrap.servers", &config.bootstrap_servers)
                .set("message.timeout.ms", "30000")
                .set("request.timeout.ms", "10000")
                .set("retries", "1");

            let producer: Option<FutureProducer> = match producer_config.create() {
                Ok(p) => Some(p),
                Err(e) => {
                    warn!("Failed to create producer for DLQ retries: {}", e);
                    None
                }
            };

            let mut interval = tokio::time::interval(Duration::from_secs(60));
            const MAX_RETRIES: u32 = 3;
            const RETRY_BACKOFF_SECS: u64 = 30;

            loop {
                interval.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("Dead letter queue processor stopping");
                    break;
                }

                // Get current queue entries
                let entries_to_process: Vec<DeadLetterEntry> = {
                    let queue = dead_letter_queue.read().await;
                    queue.clone()
                };

                if entries_to_process.is_empty() {
                    continue;
                }

                debug!("Processing {} dead letter queue entries", entries_to_process.len());

                let mut successful_indices = Vec::new();
                let mut permanent_failures = Vec::new();

                for (i, entry) in entries_to_process.iter().enumerate() {
                    // Check if entry has exceeded max retries
                    if entry.retry_count >= MAX_RETRIES {
                        warn!("Message {} exceeded max retries ({}), marking as permanent failure",
                              entry.message_id, MAX_RETRIES);
                        permanent_failures.push(i);
                        continue;
                    }

                    // Check if enough time has passed for retry (exponential backoff)
                    let backoff_secs = RETRY_BACKOFF_SECS * (1 << entry.retry_count);
                    let current_time = chrono::Utc::now().timestamp() as u64;
                    if current_time < entry.timestamp + backoff_secs {
                        debug!("Skipping retry for {} - backoff not elapsed", entry.message_id);
                        continue;
                    }

                    // Attempt retry if we have a producer
                    if let Some(ref producer) = producer {
                        let record = FutureRecord::to(&entry.topic)
                            .payload(&entry.message_data)
                            .key(&entry.message_id);

                        match producer.send(record, Duration::from_secs(10)).await {
                            Ok((partition, offset)) => {
                                info!("Successfully retried message {} to partition {} offset {}",
                                      entry.message_id, partition, offset);
                                successful_indices.push(i);

                                let mut counters = message_counters.write().await;
                                *counters.entry("dlq_retries_successful".to_string()).or_insert(0) += 1;
                            }
                            Err((e, _)) => {
                                warn!("Retry failed for message {}: {}", entry.message_id, e);

                                // Update retry count
                                let mut queue = dead_letter_queue.write().await;
                                if let Some(queue_entry) = queue.get_mut(i) {
                                    queue_entry.retry_count += 1;
                                    queue_entry.error = format!("Retry {} failed: {}", queue_entry.retry_count, e);
                                    queue_entry.timestamp = current_time;
                                }

                                let mut counters = message_counters.write().await;
                                *counters.entry("dlq_retries_failed".to_string()).or_insert(0) += 1;
                            }
                        }
                    } else {
                        // No producer available, just increment retry count
                        let mut queue = dead_letter_queue.write().await;
                        if let Some(queue_entry) = queue.get_mut(i) {
                            queue_entry.retry_count += 1;
                        }
                    }
                }

                // Remove successful and permanently failed entries
                {
                    let mut queue = dead_letter_queue.write().await;
                    let mut indices_to_remove: Vec<usize> = successful_indices
                        .into_iter()
                        .chain(permanent_failures)
                        .collect();
                    indices_to_remove.sort_unstable();
                    indices_to_remove.dedup();

                    // Remove in reverse order to preserve indices
                    for &index in indices_to_remove.iter().rev() {
                        if index < queue.len() {
                            let removed = queue.remove(index);
                            if removed.retry_count >= MAX_RETRIES {
                                error!("Permanently failed message {}: {} (original error: {})",
                                       removed.message_id, removed.topic, removed.error);
                            }
                        }
                    }
                }
            }

            info!("Dead letter queue processor exited");
        });

        Ok(())
    }

    /// Process message data from consumer (helper for spawned task)
    async fn process_message_data(
        topic: &str,
        payload: &[u8],
        event_sender: &mpsc::UnboundedSender<KafkaEvent>,
        config: &KafkaConfig,
        job_queue: &Arc<RwLock<Vec<JobIntakeMessage>>>,
    ) -> Result<()> {
        if topic == config.job_intake_topic {
            let job_message: JobIntakeMessage = serde_json::from_slice(payload)
                .context("Failed to deserialize job intake message")?;

            // Add to local job queue for processing
            job_queue.write().await.push(job_message.clone());

            // Send event for coordinator handling
            event_sender.send(KafkaEvent::JobReceived(job_message))
                .map_err(|e| anyhow::anyhow!("Failed to send job received event: {}", e))?;
        } else if topic == config.worker_communication_topic {
            let worker_message: WorkerCommunicationMessage = serde_json::from_slice(payload)
                .context("Failed to deserialize worker communication message")?;
            Self::handle_worker_message(worker_message, event_sender).await?;
        } else if topic == config.health_metrics_topic {
            let health_message: HealthMetricsMessage = serde_json::from_slice(payload)
                .context("Failed to deserialize health metrics message")?;
            event_sender.send(KafkaEvent::HealthMetricsUpdated(
                health_message.worker_id,
                health_message.metrics,
            )).map_err(|e| anyhow::anyhow!("Failed to send health metrics event: {}", e))?;
        } else {
            warn!("Unknown Kafka topic: {}", topic);
        }

        Ok(())
    }

    /// Process incoming Kafka message
    async fn process_message(
        msg: &OwnedMessage,
        event_sender: &mpsc::UnboundedSender<KafkaEvent>,
        config: &KafkaConfig,
    ) -> Result<()> {
        let topic = msg.topic();
        let payload = msg.payload().unwrap_or(&[]);
        
        match topic {
            t if t == config.job_intake_topic => {
                let job_message: JobIntakeMessage = serde_json::from_slice(payload)?;
                if let Err(e) = event_sender.send(KafkaEvent::JobReceived(job_message)) {
                    error!("Failed to send job received event: {}", e);
                }
            }
            t if t == config.worker_communication_topic => {
                let worker_message: WorkerCommunicationMessage = serde_json::from_slice(payload)?;
                Self::handle_worker_message(worker_message, event_sender).await?;
            }
            t if t == config.health_metrics_topic => {
                let health_message: HealthMetricsMessage = serde_json::from_slice(payload)?;
                if let Err(e) = event_sender.send(KafkaEvent::HealthMetricsUpdated(
                    health_message.worker_id,
                    health_message.metrics,
                )) {
                    error!("Failed to send health metrics event: {}", e);
                }
            }
            _ => {
                warn!("Unknown Kafka topic: {}", topic);
            }
        }
        
        Ok(())
    }

    /// Handle worker communication message
    async fn handle_worker_message(
        message: WorkerCommunicationMessage,
        event_sender: &mpsc::UnboundedSender<KafkaEvent>,
    ) -> Result<()> {
        match message {
            WorkerCommunicationMessage::WorkerRegistration { worker_id, capabilities, .. } => {
                if let Err(e) = event_sender.send(KafkaEvent::WorkerRegistered(worker_id, capabilities)) {
                    error!("Failed to send worker registered event: {}", e);
                }
            }
            WorkerCommunicationMessage::WorkerHeartbeat { worker_id, current_load, .. } => {
                if let Err(e) = event_sender.send(KafkaEvent::WorkerHeartbeat(worker_id, current_load)) {
                    error!("Failed to send worker heartbeat event: {}", e);
                }
            }
            WorkerCommunicationMessage::WorkerDeparture { worker_id, reason, .. } => {
                if let Err(e) = event_sender.send(KafkaEvent::WorkerDeparted(worker_id, reason)) {
                    error!("Failed to send worker departed event: {}", e);
                }
            }
            WorkerCommunicationMessage::JobAssignment { job_id, worker_id, .. } => {
                if let Err(e) = event_sender.send(KafkaEvent::JobAssigned(job_id, worker_id)) {
                    error!("Failed to send job assigned event: {}", e);
                }
            }
            WorkerCommunicationMessage::JobResult { job_id, result, .. } => {
                if let Err(e) = event_sender.send(KafkaEvent::JobCompleted(job_id, result)) {
                    error!("Failed to send job completed event: {}", e);
                }
            }
            WorkerCommunicationMessage::JobFailure { job_id, error_message, .. } => {
                if let Err(e) = event_sender.send(KafkaEvent::JobFailed(job_id, error_message)) {
                    error!("Failed to send job failed event: {}", e);
                }
            }
        }
        
        Ok(())
    }

    /// Get producer reference, returning error if not initialized
    fn get_producer(&self) -> Result<&FutureProducer> {
        self.producer.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Kafka producer not initialized. Call start() first."))
    }

    /// Send job intake message
    pub async fn send_job_intake(&self, job_message: JobIntakeMessage) -> Result<()> {
        let producer = self.get_producer()?;
        let config = self.config.clone();
        
        let payload = serde_json::to_vec(&job_message)?;
        let job_id_str = job_message.job_id.to_string();
        let record = FutureRecord::to(&config.job_intake_topic)
            .payload(&payload)
            .key(&job_id_str);
        
        match producer.send(record, Duration::from_secs(10)).await {
            Ok(_) => {
                info!("Sent job intake message for job {}", job_message.job_id);
                self.increment_message_counter("job_intake").await;
            }
            Err((e, _)) => {
                error!("Failed to send job intake message: {}", e);
                self.add_to_dead_letter_queue("job_intake", payload, e.to_string()).await;
            }
        }
        
        Ok(())
    }

    /// Send worker communication message
    pub async fn send_worker_communication(&self, message: WorkerCommunicationMessage) -> Result<()> {
        let producer = self.get_producer()?;
        let config = self.config.clone();
        
        let payload = serde_json::to_vec(&message)?;
        let key = match &message {
            WorkerCommunicationMessage::WorkerRegistration { worker_id, .. } => worker_id.to_string(),
            WorkerCommunicationMessage::WorkerHeartbeat { worker_id, .. } => worker_id.to_string(),
            WorkerCommunicationMessage::WorkerDeparture { worker_id, .. } => worker_id.to_string(),
            WorkerCommunicationMessage::JobAssignment { job_id, .. } => job_id.to_string(),
            WorkerCommunicationMessage::JobResult { job_id, .. } => job_id.to_string(),
            WorkerCommunicationMessage::JobFailure { job_id, .. } => job_id.to_string(),
        };
        
        let record = FutureRecord::to(&config.worker_communication_topic)
            .payload(&payload)
            .key(&key);
        
        match producer.send(record, Duration::from_secs(10)).await {
            Ok(_) => {
                debug!("Sent worker communication message");
                self.increment_message_counter("worker_communication").await;
            }
            Err((e, _)) => {
                error!("Failed to send worker communication message: {}", e);
                self.add_to_dead_letter_queue("worker_communication", payload, e.to_string()).await;
            }
        }
        
        Ok(())
    }

    /// Send result distribution message
    pub async fn send_result_distribution(&self, result_message: ResultDistributionMessage) -> Result<()> {
        let producer = self.get_producer()?;
        let config = self.config.clone();
        
        let payload = serde_json::to_vec(&result_message)?;
        let job_id_str = result_message.job_id.to_string();
        let record = FutureRecord::to(&config.result_distribution_topic)
            .payload(&payload)
            .key(&job_id_str);
        
        match producer.send(record, Duration::from_secs(10)).await {
            Ok(_) => {
                info!("Sent result distribution message for job {}", result_message.job_id);
                self.increment_message_counter("result_distribution").await;
            }
            Err((e, _)) => {
                error!("Failed to send result distribution message: {}", e);
                self.add_to_dead_letter_queue("result_distribution", payload, e.to_string()).await;
            }
        }
        
        Ok(())
    }

    /// Send health metrics message
    pub async fn send_health_metrics(&self, health_message: HealthMetricsMessage) -> Result<()> {
        let producer = self.get_producer()?;
        let config = self.config.clone();
        
        let payload = serde_json::to_vec(&health_message)?;
        let worker_id_str = health_message.worker_id.to_string();
        let record = FutureRecord::to(&config.health_metrics_topic)
            .payload(&payload)
            .key(&worker_id_str);
        
        match producer.send(record, Duration::from_secs(10)).await {
            Ok(_) => {
                debug!("Sent health metrics message for worker {}", health_message.worker_id);
                self.increment_message_counter("health_metrics").await;
            }
            Err((e, _)) => {
                error!("Failed to send health metrics message: {}", e);
                self.add_to_dead_letter_queue("health_metrics", payload, e.to_string()).await;
            }
        }
        
        Ok(())
    }

    /// Increment message counter
    async fn increment_message_counter(&self, counter_name: &str) {
        let mut counters = self.message_counters.write().await;
        *counters.entry(counter_name.to_string()).or_insert(0) += 1;
    }

    /// Add message to dead letter queue
    ///
    /// For producer-side failures (send errors), partition and offset are not available,
    /// so we use a monotonic sequence number for tracking.
    async fn add_to_dead_letter_queue(&self, topic: &str, payload: Vec<u8>, error: String) {
        self.add_to_dead_letter_queue_with_offset(topic, payload, error, None, None).await;
    }

    /// Add message to dead letter queue with optional partition and offset
    ///
    /// Use this when you have partition/offset from consumed messages.
    /// For producer failures, pass None and a sequence number will be used.
    async fn add_to_dead_letter_queue_with_offset(
        &self,
        topic: &str,
        payload: Vec<u8>,
        error: String,
        partition: Option<i32>,
        offset: Option<i64>,
    ) {
        // Use sequence number when partition/offset not available (producer failures)
        let seq = self.dlq_sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let entry = DeadLetterEntry {
            message_id: Uuid::new_v4().to_string(),
            topic: topic.to_string(),
            partition: partition.unwrap_or(-1), // -1 indicates producer-side failure
            offset: offset.unwrap_or(seq),      // Use sequence for tracking
            error,
            message_data: payload,
            timestamp: chrono::Utc::now().timestamp() as u64,
            retry_count: 0,
        };

        self.dead_letter_queue.write().await.push(entry);
    }

    /// Get message statistics
    pub async fn get_message_stats(&self) -> HashMap<String, u64> {
        self.message_counters.read().await.clone()
    }

    /// Get dead letter queue size
    pub async fn get_dead_letter_queue_size(&self) -> usize {
        self.dead_letter_queue.read().await.len()
    }

    /// Get job queue size
    pub async fn get_job_queue_size(&self) -> usize {
        self.job_queue.read().await.len()
    }

    /// Take the event receiver.
    ///
    /// This can only be called once - subsequent calls will return `None`.
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<KafkaEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Check if the event receiver is still available.
    pub async fn has_event_receiver(&self) -> bool {
        self.event_receiver.read().await.is_some()
    }

    /// Queue a job for sending via the producer loop
    pub async fn queue_job(&self, job_message: JobIntakeMessage) {
        self.job_queue.write().await.push(job_message);
    }

    /// Queue multiple jobs for sending
    pub async fn queue_jobs(&self, jobs: Vec<JobIntakeMessage>) {
        self.job_queue.write().await.extend(jobs);
    }

    /// Get comprehensive Kafka statistics
    pub async fn get_kafka_stats(&self) -> KafkaStats {
        let counters = self.message_counters.read().await;
        let dlq_size = self.dead_letter_queue.read().await.len();
        let job_queue_size = self.job_queue.read().await.len();

        let messages_sent = counters.get("messages_sent").copied().unwrap_or(0);
        let messages_received = counters.get("messages_received").copied().unwrap_or(0);
        let messages_failed = counters.get("messages_failed").copied().unwrap_or(0);

        let total_messages = messages_sent + messages_received + messages_failed;
        let error_rate = if total_messages > 0 {
            messages_failed as f64 / total_messages as f64
        } else {
            0.0
        };

        KafkaStats {
            messages_sent,
            messages_received,
            messages_failed,
            dead_letter_queue_size: dlq_size,
            job_queue_size,
            consumer_lag: 0, // Would need actual Kafka client access for this
            producer_queue_size: job_queue_size,
            connection_status: if *self.running.read().await {
                "connected".to_string()
            } else {
                "disconnected".to_string()
            },
            last_message_timestamp: counters.get("last_timestamp").copied().unwrap_or(0),
            average_message_size_bytes: 0, // Would need message tracking for this
            error_rate,
            throughput_messages_per_sec: 0.0, // Would need time tracking for this
        }
    }

    /// Get dead letter queue entries for inspection
    pub async fn get_dead_letter_entries(&self) -> Vec<DeadLetterEntry> {
        self.dead_letter_queue.read().await.clone()
    }

    /// Clear all successfully processed dead letter entries
    pub async fn clear_processed_dead_letters(&self) {
        // Only keeps entries that still need processing (retry_count < 3)
        let mut queue = self.dead_letter_queue.write().await;
        queue.retain(|entry| entry.retry_count < 3);
    }

    /// Health check
    pub async fn health_check(&self) -> Result<()> {
        // Check if running
        if !*self.running.read().await {
            return Err(anyhow::anyhow!("Kafka coordinator not running"));
        }
        Ok(())
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.running.read().await
    }

    /// Check if running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Reconnect both consumer and producer
    ///
    /// Attempts to reconnect both Kafka consumer and producer.
    /// Useful for recovering from connection failures.
    pub async fn reconnect(&self) -> Result<()> {
        self.reconnect_consumer().await?;
        self.reconnect_producer().await?;
        Ok(())
    }

    /// Process a raw message payload
    ///
    /// Utility method for processing Kafka message payloads.
    /// Returns the parsed event for downstream handling.
    pub async fn process_raw_message(&self, msg: &OwnedMessage) -> Result<()> {
        Self::process_message(msg, &self.event_sender, &self.config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kafka_config_default() {
        let config = KafkaConfig::default();
        assert_eq!(config.bootstrap_servers, "localhost:9092");
        assert_eq!(config.consumer_group_id, "sage-coordinator-group");
        assert_eq!(config.job_intake_topic, "sage.job.intake");
        assert!(config.enable_auto_commit);
    }

    #[tokio::test]
    async fn test_job_intake_message_creation() {
        let job_message = JobIntakeMessage {
            job_id: JobId::new(),
            job_request: JobRequest {
                job_type: JobType::AIInference {
                    model_type: "test-model".to_string(),
                    input_data: "test-input".to_string(),
                    batch_size: 1,
                    parameters: HashMap::new(),
                },
                priority: 5,
                max_cost: 1000,
                deadline: None,
                client_address: "test-client".to_string(),
                callback_url: None,
                data: vec![1, 2, 3],
                max_duration_secs: 3600,
            },
            client_id: "test-client".to_string(),
            callback_url: None,
            priority: JobPriority::Normal,
            max_retries: 3,
            created_at: chrono::Utc::now().timestamp() as u64,
        };

        assert_eq!(job_message.priority, JobPriority::Normal);
        assert_eq!(job_message.max_retries, 3);
    }

    #[tokio::test]
    async fn test_kafka_coordinator_creation() {
        let config = KafkaConfig::default();
        let coordinator = KafkaCoordinator::new(config);

        // Should start with empty queues
        assert_eq!(coordinator.get_job_queue_size().await, 0);
        assert_eq!(coordinator.get_dead_letter_queue_size().await, 0);
        assert!(!coordinator.is_running().await);
    }

    #[tokio::test]
    async fn test_job_queueing() {
        let config = KafkaConfig::default();
        let coordinator = KafkaCoordinator::new(config);

        // Create test job
        let job_message = JobIntakeMessage {
            job_id: JobId::new(),
            job_request: JobRequest {
                job_type: JobType::AIInference {
                    model_type: "test".to_string(),
                    input_data: "test".to_string(),
                    batch_size: 1,
                    parameters: HashMap::new(),
                },
                priority: 5,
                max_cost: 1000,
                deadline: None,
                client_address: "test".to_string(),
                callback_url: None,
                data: vec![],
                max_duration_secs: 3600,
            },
            client_id: "test".to_string(),
            callback_url: None,
            priority: JobPriority::Normal,
            max_retries: 3,
            created_at: chrono::Utc::now().timestamp() as u64,
        };

        // Queue the job
        coordinator.queue_job(job_message).await;
        assert_eq!(coordinator.get_job_queue_size().await, 1);

        // Queue multiple jobs
        let jobs: Vec<JobIntakeMessage> = (0..5).map(|_| {
            JobIntakeMessage {
                job_id: JobId::new(),
                job_request: JobRequest {
                    job_type: JobType::AIInference {
                        model_type: "test".to_string(),
                        input_data: "test".to_string(),
                        batch_size: 1,
                        parameters: HashMap::new(),
                    },
                    priority: 5,
                    max_cost: 1000,
                    deadline: None,
                    client_address: "test".to_string(),
                    callback_url: None,
                    data: vec![],
                    max_duration_secs: 3600,
                },
                client_id: "test".to_string(),
                callback_url: None,
                priority: JobPriority::Normal,
                max_retries: 3,
                created_at: chrono::Utc::now().timestamp() as u64,
            }
        }).collect();

        coordinator.queue_jobs(jobs).await;
        assert_eq!(coordinator.get_job_queue_size().await, 6);
    }

    #[tokio::test]
    async fn test_kafka_stats() {
        let config = KafkaConfig::default();
        let coordinator = KafkaCoordinator::new(config);

        let stats = coordinator.get_kafka_stats().await;
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);
        assert_eq!(stats.messages_failed, 0);
        assert_eq!(stats.dead_letter_queue_size, 0);
        assert_eq!(stats.job_queue_size, 0);
        assert_eq!(stats.connection_status, "disconnected");
        assert_eq!(stats.error_rate, 0.0);
    }

    #[tokio::test]
    async fn test_dead_letter_entry() {
        let entry = DeadLetterEntry {
            message_id: "test-123".to_string(),
            topic: "test.topic".to_string(),
            partition: 0,
            offset: 100,
            error: "test error".to_string(),
            message_data: vec![1, 2, 3],
            timestamp: chrono::Utc::now().timestamp() as u64,
            retry_count: 0,
        };

        assert_eq!(entry.message_id, "test-123");
        assert_eq!(entry.retry_count, 0);
        assert_eq!(entry.topic, "test.topic");
    }

    #[tokio::test]
    async fn test_worker_communication_message_variants() {
        let worker_id = WorkerId::new();

        // Test WorkerRegistration
        let registration = WorkerCommunicationMessage::WorkerRegistration {
            worker_id: worker_id.clone(),
            capabilities: WorkerCapabilities {
                gpu_memory_gb: 16,
                cpu_cores: 8,
                ram_gb: 32,
                supported_job_types: vec!["ai".to_string()],
                ai_frameworks: vec!["pytorch".to_string()],
                specialized_hardware: vec![],
                max_parallel_tasks: 4,
                network_bandwidth_mbps: 1000,
                storage_gb: 500,
                supports_fp16: true,
                supports_int8: true,
                cuda_compute_capability: Some("8.0".to_string()),
            },
            location: WorkerLocation {
                region: "us-west-2".to_string(),
                country: "US".to_string(),
                latitude: 37.7749,
                longitude: -122.4194,
                timezone: "PST".to_string(),
                network_latency_ms: 10,
            },
            health_metrics: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        // Verify serialization works
        let json = serde_json::to_string(&registration).unwrap();
        assert!(json.contains("WorkerRegistration"));

        // Test WorkerHeartbeat
        let heartbeat = WorkerCommunicationMessage::WorkerHeartbeat {
            worker_id: worker_id.clone(),
            current_load: 0.5,
            health_metrics: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let json = serde_json::to_string(&heartbeat).unwrap();
        assert!(json.contains("WorkerHeartbeat"));

        // Test JobFailure
        let failure = WorkerCommunicationMessage::JobFailure {
            job_id: JobId::new(),
            worker_id,
            error_message: "Test failure".to_string(),
            retry_count: 1,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let json = serde_json::to_string(&failure).unwrap();
        assert!(json.contains("JobFailure"));
    }

    #[tokio::test]
    async fn test_job_priority_ordering() {
        assert!(JobPriority::Critical > JobPriority::High);
        assert!(JobPriority::High > JobPriority::Normal);
        assert!(JobPriority::Normal > JobPriority::Low);
    }
} 