-- CIRO Network Database Schema
-- Migration 001: Initial Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Jobs table: Store job metadata and state
CREATE TABLE jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id VARCHAR(255) UNIQUE NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    priority VARCHAR(10) NOT NULL DEFAULT 'medium',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Job parameters and metadata
    parameters JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    
    -- Resource requirements
    cpu_cores INTEGER,
    memory_mb INTEGER,
    gpu_memory_mb INTEGER,
    storage_gb INTEGER,
    
    -- Results and outputs
    result JSONB,
    output_files TEXT[],
    error_message TEXT,
    
    -- Performance metrics
    total_tasks INTEGER DEFAULT 0,
    completed_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,
    processing_time_ms BIGINT,
    
    -- Parallelization strategy
    parallelization_strategy VARCHAR(50),
    chunk_size INTEGER,
    
    CONSTRAINT valid_status CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_priority CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    CONSTRAINT valid_job_type CHECK (job_type IN ('3d_rendering', 'video_processing', 'ai_inference', 'computer_vision', 'nlp', 'audio_processing', 'time_series_analysis', 'multimodal_ai', 'reinforcement_learning', 'specialized_ai', 'zk_proof', 'custom'))
);

-- Workers table: Track worker registration and capabilities
CREATE TABLE workers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    worker_id VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'offline',
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Worker capabilities
    capabilities JSONB NOT NULL DEFAULT '{}',
    cpu_cores INTEGER NOT NULL DEFAULT 0,
    memory_mb INTEGER NOT NULL DEFAULT 0,
    gpu_memory_mb INTEGER NOT NULL DEFAULT 0,
    storage_gb INTEGER NOT NULL DEFAULT 0,
    
    -- Network information
    ip_address INET,
    port INTEGER,
    public_key TEXT,
    
    -- Performance metrics
    jobs_completed INTEGER DEFAULT 0,
    jobs_failed INTEGER DEFAULT 0,
    total_compute_time_ms BIGINT DEFAULT 0,
    average_response_time_ms INTEGER DEFAULT 0,
    reputation_score DECIMAL(3,2) DEFAULT 5.00,
    
    -- Worker metadata
    version VARCHAR(50),
    os_info VARCHAR(100),
    hardware_info JSONB DEFAULT '{}',
    
    CONSTRAINT valid_worker_status CHECK (status IN ('offline', 'idle', 'busy', 'maintenance', 'error')),
    CONSTRAINT valid_reputation CHECK (reputation_score >= 0.00 AND reputation_score <= 10.00)
);

-- Tasks table: Individual task tracking within jobs
CREATE TABLE tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id VARCHAR(255) UNIQUE NOT NULL,
    job_id VARCHAR(255) NOT NULL,
    worker_id VARCHAR(255),
    
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Task specifics
    task_type VARCHAR(50) NOT NULL,
    sequence_number INTEGER NOT NULL,
    dependencies TEXT[],
    
    -- Task parameters and data
    parameters JSONB NOT NULL DEFAULT '{}',
    input_data JSONB,
    output_data JSONB,
    
    -- Resource usage
    cpu_usage_percent DECIMAL(5,2),
    memory_usage_mb INTEGER,
    gpu_usage_percent DECIMAL(5,2),
    processing_time_ms BIGINT,
    
    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    
    CONSTRAINT valid_task_status CHECK (status IN ('pending', 'assigned', 'processing', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_retry_count CHECK (retry_count >= 0 AND retry_count <= max_retries),
    
    -- Foreign key constraints
    CONSTRAINT fk_tasks_job_id FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE,
    CONSTRAINT fk_tasks_worker_id FOREIGN KEY (worker_id) REFERENCES workers(worker_id) ON DELETE SET NULL
);

-- System state table: Overall coordinator state management
CREATE TABLE system_state (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    coordinator_id VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'initializing',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- System metrics
    active_jobs INTEGER DEFAULT 0,
    active_workers INTEGER DEFAULT 0,
    total_jobs_processed INTEGER DEFAULT 0,
    total_tasks_processed INTEGER DEFAULT 0,
    
    -- Configuration
    configuration JSONB NOT NULL DEFAULT '{}',
    
    -- Performance metrics
    average_job_completion_time_ms BIGINT DEFAULT 0,
    system_load_percent DECIMAL(5,2) DEFAULT 0.00,
    
    CONSTRAINT valid_system_status CHECK (status IN ('initializing', 'running', 'maintenance', 'shutting_down', 'error'))
);

-- Job history table: Archive completed jobs for analytics
CREATE TABLE job_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id VARCHAR(255) NOT NULL,
    archived_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Copy of job data for historical analysis
    job_data JSONB NOT NULL,
    performance_metrics JSONB NOT NULL DEFAULT '{}',
    
    -- Indexing for analytics
    job_type VARCHAR(50) NOT NULL,
    completion_time_ms BIGINT,
    total_tasks INTEGER,
    worker_count INTEGER
);

-- Performance indexes for optimal query performance
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_job_type ON jobs(job_type);
CREATE INDEX idx_jobs_created_at ON jobs(created_at);
CREATE INDEX idx_jobs_priority ON jobs(priority);

CREATE INDEX idx_workers_status ON workers(status);
CREATE INDEX idx_workers_last_heartbeat ON workers(last_heartbeat);
CREATE INDEX idx_workers_reputation ON workers(reputation_score);

CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_job_id ON tasks(job_id);
CREATE INDEX idx_tasks_worker_id ON tasks(worker_id);
CREATE INDEX idx_tasks_created_at ON tasks(created_at);

CREATE INDEX idx_job_history_job_type ON job_history(job_type);
CREATE INDEX idx_job_history_archived_at ON job_history(archived_at);

-- Triggers for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_jobs_updated_at BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_workers_updated_at BEFORE UPDATE ON workers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_state_updated_at BEFORE UPDATE ON system_state
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Events table: Store blockchain events from monitored contracts
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    contract_address VARCHAR(66) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    block_number BIGINT NOT NULL,
    timestamp BIGINT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_events_contract_address ON events (contract_address);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_block_number ON events (block_number);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at); 