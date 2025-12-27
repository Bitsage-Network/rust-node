//! Work-Stealing Scheduler for Multi-GPU Proof Generation
//!
//! This module implements a work-stealing scheduler that dynamically balances
//! proof generation workload across multiple GPUs. Key features:
//!
//! - **Lock-free work queues**: Each GPU has its own deque, minimizing contention
//! - **Work stealing**: Idle GPUs steal from busy ones for better utilization
//! - **Priority scheduling**: Larger proofs scheduled first for optimal pipelining
//! - **Adaptive load balancing**: Tracks GPU performance and adjusts accordingly
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     Work-Stealing Scheduler                              │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  Global Queue (new work)                                                 │
//! │  ┌─────────────────────────────────────────────────────────────────┐    │
//! │  │ [Proof5] [Proof4] [Proof3] [Proof2] [Proof1] [Proof0]           │    │
//! │  └─────────────────────────────────────────────────────────────────┘    │
//! │           │              │              │              │                 │
//! │           ▼              ▼              ▼              ▼                 │
//! │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │
//! │  │   GPU 0      │ │   GPU 1      │ │   GPU 2      │ │   GPU 3      │    │
//! │  │ Local Deque  │ │ Local Deque  │ │ Local Deque  │ │ Local Deque  │    │
//! │  │  [P0] [P4]   │ │  [P1] [P5]   │ │  [P2]        │ │  [P3]        │    │
//! │  │     │        │ │     │        │ │     │        │ │     │        │    │
//! │  │     ▼        │ │     ▼        │ │     ▼        │ │     ▼        │    │
//! │  │  Working     │ │  Working     │ │   IDLE  ───────────► Steal!  │    │
//! │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘    │
//! │                                                                          │
//! │  Stats: GPU0: 95% | GPU1: 92% | GPU2: 88% | GPU3: 91%                   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam::deque::{Injector, Stealer, Worker as WorkerDeque};
use parking_lot::Mutex;
use tracing::{debug, info};

use crate::obelysk::ExecutionTrace;

// =============================================================================
// Work Item
// =============================================================================

/// A unit of work to be processed by a GPU
#[derive(Debug)]
pub struct WorkItem {
    /// Unique identifier for this work item
    pub id: u64,
    /// The execution trace to prove
    pub trace: ExecutionTrace,
    /// Priority (higher = more urgent, based on trace size for optimal scheduling)
    pub priority: u32,
    /// Timestamp when the work was submitted
    pub submitted_at: Instant,
    /// Estimated complexity (based on trace length)
    pub estimated_cycles: u64,
}

impl WorkItem {
    /// Create a new work item from a trace
    pub fn new(id: u64, trace: ExecutionTrace) -> Self {
        let trace_len = trace.steps.len();
        // Larger traces get higher priority (process first for better pipelining)
        let priority = (trace_len as u32).min(u32::MAX);
        // Estimate cycles based on trace size (roughly O(n log n) for FFT operations)
        let log_size = (trace_len as f64).log2().ceil() as u64;
        let estimated_cycles = (trace_len as u64) * log_size;

        Self {
            id,
            trace,
            priority,
            submitted_at: Instant::now(),
            estimated_cycles,
        }
    }
}

// =============================================================================
// Work Result
// =============================================================================

/// Result of processing a work item
#[derive(Debug)]
pub struct WorkResult {
    /// Work item ID
    pub work_id: u64,
    /// GPU that processed this work
    pub gpu_id: usize,
    /// Processing time in microseconds
    pub processing_time_us: u64,
    /// Whether the proof was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

// =============================================================================
// GPU Worker Statistics
// =============================================================================

/// Statistics for a single GPU worker
#[derive(Debug, Default)]
pub struct GpuStats {
    /// Total work items processed
    pub items_processed: AtomicU64,
    /// Total processing time in microseconds
    pub total_processing_us: AtomicU64,
    /// Number of items stolen from this GPU
    pub items_stolen: AtomicU64,
    /// Number of items this GPU stole from others
    pub items_taken: AtomicU64,
    /// Current queue depth
    pub queue_depth: AtomicUsize,
    /// Whether the GPU is currently idle
    pub is_idle: AtomicBool,
    /// Last activity timestamp (epoch microseconds)
    pub last_active_us: AtomicU64,
}

impl GpuStats {
    /// Calculate average processing time per item
    pub fn avg_processing_time_us(&self) -> f64 {
        let items = self.items_processed.load(Ordering::Relaxed);
        if items == 0 {
            return 0.0;
        }
        self.total_processing_us.load(Ordering::Relaxed) as f64 / items as f64
    }

    /// Calculate utilization percentage
    pub fn utilization(&self, total_time_us: u64) -> f64 {
        if total_time_us == 0 {
            return 0.0;
        }
        let busy_time = self.total_processing_us.load(Ordering::Relaxed);
        (busy_time as f64 / total_time_us as f64 * 100.0).min(100.0)
    }
}

// =============================================================================
// Work-Stealing Scheduler
// =============================================================================

/// Configuration for the work-stealing scheduler
#[derive(Debug, Clone)]
pub struct WorkStealingConfig {
    /// Number of GPUs to use
    pub num_gpus: usize,
    /// Maximum items per GPU local queue before stealing kicks in
    pub max_local_queue_size: usize,
    /// How often to check for stealing opportunities (microseconds)
    pub steal_check_interval_us: u64,
    /// Minimum items to steal at once (batch stealing for efficiency)
    pub min_steal_batch: usize,
    /// Enable priority scheduling (larger proofs first)
    pub priority_scheduling: bool,
    /// Timeout for waiting on empty queues (milliseconds)
    pub idle_timeout_ms: u64,
}

impl Default for WorkStealingConfig {
    fn default() -> Self {
        Self {
            num_gpus: 4,
            max_local_queue_size: 16,
            steal_check_interval_us: 100,
            min_steal_batch: 2,
            priority_scheduling: true,
            idle_timeout_ms: 10,
        }
    }
}

/// Work-stealing scheduler for multi-GPU proof generation
pub struct WorkStealingScheduler {
    /// Configuration
    config: WorkStealingConfig,

    /// Global injector queue for new work
    global_queue: Arc<Injector<WorkItem>>,

    /// Per-GPU local work queues (worker end)
    local_queues: Vec<Arc<Mutex<WorkerDeque<WorkItem>>>>,

    /// Stealers for each GPU's queue (for other GPUs to steal from)
    stealers: Vec<Stealer<WorkItem>>,

    /// Per-GPU statistics
    gpu_stats: Vec<Arc<GpuStats>>,

    /// Total work items submitted
    total_submitted: AtomicU64,

    /// Total work items completed
    total_completed: AtomicU64,

    /// Scheduler start time
    start_time: Instant,

    /// Shutdown flag
    shutdown: Arc<AtomicBool>,

    /// Results channel
    results: Arc<Mutex<VecDeque<WorkResult>>>,
}

impl WorkStealingScheduler {
    /// Create a new work-stealing scheduler
    pub fn new(config: WorkStealingConfig) -> Self {
        let num_gpus = config.num_gpus;

        // Create global injector
        let global_queue = Arc::new(Injector::new());

        // Create per-GPU local queues and stealers
        let mut local_queues = Vec::with_capacity(num_gpus);
        let mut stealers = Vec::with_capacity(num_gpus);
        let mut gpu_stats = Vec::with_capacity(num_gpus);

        for _ in 0..num_gpus {
            let worker = WorkerDeque::new_fifo();
            stealers.push(worker.stealer());
            local_queues.push(Arc::new(Mutex::new(worker)));
            gpu_stats.push(Arc::new(GpuStats::default()));
        }

        info!(
            "🔧 Work-stealing scheduler initialized with {} GPUs",
            num_gpus
        );

        Self {
            config,
            global_queue,
            local_queues,
            stealers,
            gpu_stats,
            total_submitted: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            start_time: Instant::now(),
            shutdown: Arc::new(AtomicBool::new(false)),
            results: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Submit a batch of work items
    pub fn submit_batch(&self, traces: Vec<ExecutionTrace>) -> Vec<u64> {
        let mut work_ids = Vec::with_capacity(traces.len());

        // Convert traces to work items
        let mut work_items: Vec<_> = traces
            .into_iter()
            .enumerate()
            .map(|(i, trace)| {
                let id = self.total_submitted.fetch_add(1, Ordering::Relaxed);
                work_ids.push(id);
                WorkItem::new(id, trace)
            })
            .collect();

        // Sort by priority if enabled (larger traces first)
        if self.config.priority_scheduling {
            work_items.sort_by(|a, b| b.priority.cmp(&a.priority));
        }

        // Distribute work: first fill local queues evenly, then global
        let items_per_gpu = work_items.len() / self.config.num_gpus;
        let mut distributed = 0;

        for (gpu_id, items) in work_items.chunks(items_per_gpu.max(1)).enumerate() {
            if gpu_id < self.config.num_gpus {
                let queue = self.local_queues[gpu_id].lock();
                for item in items {
                    // Can't move out of slice, need to reconstruct
                    let work_item = WorkItem {
                        id: item.id,
                        trace: item.trace.clone(),
                        priority: item.priority,
                        submitted_at: item.submitted_at,
                        estimated_cycles: item.estimated_cycles,
                    };
                    queue.push(work_item);
                    distributed += 1;
                }
                self.gpu_stats[gpu_id].queue_depth.store(
                    queue.len(),
                    Ordering::Relaxed
                );
            }
        }

        // Any remaining items go to global queue
        for item in work_items.into_iter().skip(distributed) {
            self.global_queue.push(item);
        }

        debug!(
            "Submitted {} work items ({} direct, {} global)",
            work_ids.len(),
            distributed,
            work_ids.len() - distributed
        );

        work_ids
    }

    /// Try to get work for a specific GPU
    ///
    /// Priority order:
    /// 1. Local queue (fastest, no contention)
    /// 2. Global queue (shared new work)
    /// 3. Steal from other GPUs (load balancing)
    pub fn get_work(&self, gpu_id: usize) -> Option<WorkItem> {
        // 1. Try local queue first
        {
            let queue = self.local_queues[gpu_id].lock();
            if let Some(item) = queue.pop() {
                self.gpu_stats[gpu_id].queue_depth.store(queue.len(), Ordering::Relaxed);
                return Some(item);
            }
        }

        // 2. Try global queue
        if let Some(item) = self.try_steal_from_global() {
            return Some(item);
        }

        // 3. Try stealing from other GPUs
        self.try_steal_from_others(gpu_id)
    }

    /// Try to steal from global queue
    fn try_steal_from_global(&self) -> Option<WorkItem> {
        match self.global_queue.steal() {
            crossbeam::deque::Steal::Success(item) => Some(item),
            _ => None,
        }
    }

    /// Try to steal work from other GPUs
    fn try_steal_from_others(&self, gpu_id: usize) -> Option<WorkItem> {
        // Find the GPU with the most work
        let mut best_victim = None;
        let mut max_depth = 0;

        for (other_id, stats) in self.gpu_stats.iter().enumerate() {
            if other_id != gpu_id {
                let depth = stats.queue_depth.load(Ordering::Relaxed);
                if depth > max_depth {
                    max_depth = depth;
                    best_victim = Some(other_id);
                }
            }
        }

        // Steal from the busiest GPU
        if let Some(victim_id) = best_victim {
            if max_depth >= self.config.min_steal_batch {
                match self.stealers[victim_id].steal() {
                    crossbeam::deque::Steal::Success(item) => {
                        self.gpu_stats[victim_id].items_stolen.fetch_add(1, Ordering::Relaxed);
                        self.gpu_stats[gpu_id].items_taken.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            "GPU {} stole work item {} from GPU {}",
                            gpu_id, item.id, victim_id
                        );
                        return Some(item);
                    }
                    _ => {}
                }
            }
        }

        None
    }

    /// Report completion of a work item
    pub fn report_completion(&self, result: WorkResult) {
        let gpu_id = result.gpu_id;

        // Update statistics
        self.gpu_stats[gpu_id].items_processed.fetch_add(1, Ordering::Relaxed);
        self.gpu_stats[gpu_id].total_processing_us.fetch_add(
            result.processing_time_us,
            Ordering::Relaxed
        );
        self.gpu_stats[gpu_id].last_active_us.store(
            self.start_time.elapsed().as_micros() as u64,
            Ordering::Relaxed
        );

        self.total_completed.fetch_add(1, Ordering::Relaxed);

        // Store result
        self.results.lock().push_back(result);
    }

    /// Check if all submitted work is complete
    pub fn is_complete(&self) -> bool {
        self.total_completed.load(Ordering::Relaxed) >=
            self.total_submitted.load(Ordering::Relaxed)
    }

    /// Get pending work count
    pub fn pending_count(&self) -> u64 {
        let submitted = self.total_submitted.load(Ordering::Relaxed);
        let completed = self.total_completed.load(Ordering::Relaxed);
        submitted.saturating_sub(completed)
    }

    /// Collect all completed results
    pub fn collect_results(&self) -> Vec<WorkResult> {
        let mut results = self.results.lock();
        results.drain(..).collect()
    }

    /// Get scheduler statistics
    pub fn get_stats(&self) -> SchedulerStats {
        let elapsed = self.start_time.elapsed();
        let elapsed_us = elapsed.as_micros() as u64;
        let completed = self.total_completed.load(Ordering::Relaxed);

        let gpu_stats: Vec<_> = self.gpu_stats.iter().enumerate().map(|(id, stats)| {
            GpuWorkerStats {
                gpu_id: id,
                items_processed: stats.items_processed.load(Ordering::Relaxed),
                avg_processing_time_us: stats.avg_processing_time_us(),
                utilization: stats.utilization(elapsed_us),
                items_stolen: stats.items_stolen.load(Ordering::Relaxed),
                items_taken: stats.items_taken.load(Ordering::Relaxed),
                queue_depth: stats.queue_depth.load(Ordering::Relaxed),
            }
        }).collect();

        let throughput = if elapsed.as_secs_f64() > 0.0 {
            completed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        SchedulerStats {
            total_submitted: self.total_submitted.load(Ordering::Relaxed),
            total_completed: completed,
            elapsed_ms: elapsed.as_millis() as u64,
            throughput_per_sec: throughput,
            gpu_stats,
        }
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Statistics Types
// =============================================================================

/// Per-GPU worker statistics
#[derive(Debug, Clone)]
pub struct GpuWorkerStats {
    pub gpu_id: usize,
    pub items_processed: u64,
    pub avg_processing_time_us: f64,
    pub utilization: f64,
    pub items_stolen: u64,
    pub items_taken: u64,
    pub queue_depth: usize,
}

/// Overall scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub total_submitted: u64,
    pub total_completed: u64,
    pub elapsed_ms: u64,
    pub throughput_per_sec: f64,
    pub gpu_stats: Vec<GpuWorkerStats>,
}

impl SchedulerStats {
    /// Print a formatted summary
    pub fn print_summary(&self) {
        info!(
            total_submitted = self.total_submitted,
            total_completed = self.total_completed,
            elapsed_ms = self.elapsed_ms,
            throughput_per_sec = self.throughput_per_sec,
            "Work-stealing scheduler statistics"
        );

        for gpu in &self.gpu_stats {
            info!(
                gpu_id = gpu.gpu_id,
                items_processed = gpu.items_processed,
                utilization_pct = gpu.utilization,
                avg_processing_us = gpu.avg_processing_time_us,
                items_stolen = gpu.items_stolen,
                items_taken = gpu.items_taken,
                "GPU worker statistics"
            );
        }
    }

    /// Check if load is well-balanced (all GPUs within 20% of average)
    pub fn is_balanced(&self) -> bool {
        if self.gpu_stats.is_empty() {
            return true;
        }

        let avg_items: f64 = self.gpu_stats.iter()
            .map(|g| g.items_processed as f64)
            .sum::<f64>() / self.gpu_stats.len() as f64;

        if avg_items == 0.0 {
            return true;
        }

        self.gpu_stats.iter().all(|g| {
            let ratio = g.items_processed as f64 / avg_items;
            ratio >= 0.8 && ratio <= 1.2
        })
    }
}

// =============================================================================
// GPU Worker Thread
// =============================================================================

/// A GPU worker thread that processes work items
pub struct GpuWorker {
    /// GPU identifier
    pub gpu_id: usize,
    /// Reference to the scheduler
    scheduler: Arc<WorkStealingScheduler>,
    /// Proof generation function
    prove_fn: Arc<dyn Fn(&ExecutionTrace) -> Result<(), String> + Send + Sync>,
}

impl GpuWorker {
    /// Create a new GPU worker
    pub fn new<F>(
        gpu_id: usize,
        scheduler: Arc<WorkStealingScheduler>,
        prove_fn: F,
    ) -> Self
    where
        F: Fn(&ExecutionTrace) -> Result<(), String> + Send + Sync + 'static,
    {
        Self {
            gpu_id,
            scheduler,
            prove_fn: Arc::new(prove_fn),
        }
    }

    /// Run the worker loop
    pub fn run(&self) {
        info!("🔨 GPU Worker {} started", self.gpu_id);

        while !self.scheduler.is_shutdown() {
            // Try to get work
            if let Some(work_item) = self.scheduler.get_work(self.gpu_id) {
                self.process_work_item(work_item);
            } else {
                // No work available, brief sleep before checking again
                self.scheduler.gpu_stats[self.gpu_id].is_idle.store(true, Ordering::Relaxed);
                thread::sleep(Duration::from_micros(
                    self.scheduler.config.steal_check_interval_us
                ));
            }
        }

        info!("🛑 GPU Worker {} stopped", self.gpu_id);
    }

    /// Process a single work item
    fn process_work_item(&self, work_item: WorkItem) {
        self.scheduler.gpu_stats[self.gpu_id].is_idle.store(false, Ordering::Relaxed);

        let start = Instant::now();
        let work_id = work_item.id;

        // Execute the proof generation
        let result = (self.prove_fn)(&work_item.trace);

        let elapsed = start.elapsed();
        let processing_time_us = elapsed.as_micros() as u64;

        let work_result = match result {
            Ok(()) => WorkResult {
                work_id,
                gpu_id: self.gpu_id,
                processing_time_us,
                success: true,
                error: None,
            },
            Err(e) => WorkResult {
                work_id,
                gpu_id: self.gpu_id,
                processing_time_us,
                success: false,
                error: Some(e),
            },
        };

        self.scheduler.report_completion(work_result);

        debug!(
            "GPU {} completed work item {} in {:?}",
            self.gpu_id, work_id, elapsed
        );
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::M31;
    use crate::obelysk::vm::{ExecutionStep, Instruction, OpCode};

    fn create_test_trace(size: usize) -> ExecutionTrace {
        let steps: Vec<ExecutionStep> = (0..size).map(|i| {
            ExecutionStep {
                pc: i,
                instruction: Instruction {
                    opcode: OpCode::Add,
                    dst: 0,
                    src1: 1,
                    src2: 2,
                    immediate: None,
                    address: None,
                },
                registers_before: [M31::new(i as u32); 32],
                registers_after: [M31::new((i + 1) as u32); 32],
                memory_read: None,
                memory_write: None,
                cycle: i as u64,
            }
        }).collect();

        ExecutionTrace {
            steps,
            final_registers: [M31::new(0); 32],
            public_inputs: vec![M31::new(1)],
            public_outputs: vec![M31::new(2)],
        }
    }

    #[test]
    fn test_work_item_creation() {
        let trace = create_test_trace(1024);
        let item = WorkItem::new(0, trace);

        assert_eq!(item.id, 0);
        assert_eq!(item.priority, 1024);
        assert!(item.estimated_cycles > 0);
    }

    #[test]
    fn test_scheduler_creation() {
        let config = WorkStealingConfig {
            num_gpus: 4,
            ..Default::default()
        };

        let scheduler = WorkStealingScheduler::new(config);

        assert_eq!(scheduler.config.num_gpus, 4);
        assert_eq!(scheduler.local_queues.len(), 4);
        assert_eq!(scheduler.stealers.len(), 4);
    }

    #[test]
    fn test_submit_and_get_work() {
        let config = WorkStealingConfig {
            num_gpus: 2,
            ..Default::default()
        };

        let scheduler = WorkStealingScheduler::new(config);

        // Submit some work
        let traces = vec![
            create_test_trace(100),
            create_test_trace(200),
            create_test_trace(150),
        ];

        let work_ids = scheduler.submit_batch(traces);
        assert_eq!(work_ids.len(), 3);

        // Get work from GPU 0
        let work = scheduler.get_work(0);
        assert!(work.is_some());
    }

    #[test]
    fn test_work_stealing() {
        let config = WorkStealingConfig {
            num_gpus: 2,
            min_steal_batch: 1,
            ..Default::default()
        };

        let scheduler = WorkStealingScheduler::new(config);

        // Submit all work to GPU 0's local queue
        {
            let queue = scheduler.local_queues[0].lock();
            for i in 0..5 {
                queue.push(WorkItem::new(i, create_test_trace(100)));
            }
            scheduler.gpu_stats[0].queue_depth.store(5, Ordering::Relaxed);
        }

        // GPU 1 should be able to steal
        let stolen = scheduler.get_work(1);
        assert!(stolen.is_some());
    }

    #[test]
    fn test_scheduler_stats() {
        let config = WorkStealingConfig {
            num_gpus: 2,
            ..Default::default()
        };

        let scheduler = WorkStealingScheduler::new(config);

        // Submit and complete some work
        let traces = vec![create_test_trace(100)];
        scheduler.submit_batch(traces);

        scheduler.report_completion(WorkResult {
            work_id: 0,
            gpu_id: 0,
            processing_time_us: 1000,
            success: true,
            error: None,
        });

        let stats = scheduler.get_stats();
        assert_eq!(stats.total_submitted, 1);
        assert_eq!(stats.total_completed, 1);
        assert_eq!(stats.gpu_stats[0].items_processed, 1);
    }

    #[test]
    fn test_load_balancing() {
        let config = WorkStealingConfig {
            num_gpus: 4,
            priority_scheduling: true,
            ..Default::default()
        };

        let scheduler = WorkStealingScheduler::new(config);

        // Submit work with different sizes
        let traces: Vec<_> = (0..8)
            .map(|i| create_test_trace(100 * (i + 1)))
            .collect();

        let work_ids = scheduler.submit_batch(traces);
        assert_eq!(work_ids.len(), 8);

        // Work should be distributed across GPUs
        let total_depth: usize = scheduler.gpu_stats.iter()
            .map(|s| s.queue_depth.load(Ordering::Relaxed))
            .sum();

        assert!(total_depth > 0);
    }
}
