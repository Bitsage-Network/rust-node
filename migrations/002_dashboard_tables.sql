-- =====================================================
-- BitSage Network - Dashboard Support Tables
-- Version: 1.0.1
-- Date: 2026-01-15
--
-- Adds tables required for validator dashboard:
-- - heartbeats: Worker uptime tracking
-- - reward_claims: Reward claim history
-- - gpu_metrics_history: Historical GPU performance data
-- =====================================================

-- =====================================================
-- HEARTBEATS TABLE (Worker Uptime Tracking)
-- =====================================================

CREATE TABLE IF NOT EXISTS heartbeats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_address TEXT NOT NULL,
    worker_id TEXT,
    heartbeat_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    gpu_count INTEGER DEFAULT 1,
    gpu_utilization_avg NUMERIC(5, 2),
    memory_utilization_avg NUMERIC(5, 2),
    jobs_in_progress INTEGER DEFAULT 0,
    latency_ms INTEGER,
    version TEXT,
    ip_hash TEXT,  -- Hashed IP for privacy
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for efficient uptime queries
CREATE INDEX IF NOT EXISTS idx_heartbeats_worker ON heartbeats(worker_address);
CREATE INDEX IF NOT EXISTS idx_heartbeats_time ON heartbeats(heartbeat_time DESC);
CREATE INDEX IF NOT EXISTS idx_heartbeats_worker_time ON heartbeats(worker_address, heartbeat_time DESC);

-- Partition by time for efficient cleanup (optional - for high-volume deployments)
-- Can be enabled later with: ALTER TABLE heartbeats PARTITION BY RANGE (heartbeat_time);

-- =====================================================
-- REWARD CLAIMS TABLE (Claim History)
-- =====================================================

CREATE TABLE IF NOT EXISTS reward_claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address TEXT NOT NULL,
    amount NUMERIC(78, 0) NOT NULL,
    claim_type TEXT NOT NULL DEFAULT 'staking', -- 'staking', 'mining', 'referral', 'bonus'
    claim_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    epoch_number INTEGER,  -- Reward epoch if applicable
    tx_hash TEXT,
    block_number BIGINT,
    status TEXT NOT NULL DEFAULT 'completed' -- 'pending', 'completed', 'failed'
);

CREATE INDEX IF NOT EXISTS idx_claims_address ON reward_claims(address);
CREATE INDEX IF NOT EXISTS idx_claims_time ON reward_claims(claim_time DESC);
CREATE INDEX IF NOT EXISTS idx_claims_type ON reward_claims(claim_type);
CREATE INDEX IF NOT EXISTS idx_claims_status ON reward_claims(status);

-- =====================================================
-- GPU METRICS HISTORY TABLE (Performance Trends)
-- =====================================================

CREATE TABLE IF NOT EXISTS gpu_metrics_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_address TEXT NOT NULL,
    gpu_index INTEGER NOT NULL DEFAULT 0,
    gpu_model TEXT,
    gpu_tier TEXT,
    vram_total_gb NUMERIC(10, 2),
    vram_used_gb NUMERIC(10, 2),
    compute_utilization NUMERIC(5, 2),
    temperature_celsius NUMERIC(5, 2),
    power_watts NUMERIC(8, 2),
    has_tee BOOLEAN DEFAULT FALSE,
    current_job_id TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gpu_metrics_worker ON gpu_metrics_history(worker_address);
CREATE INDEX IF NOT EXISTS idx_gpu_metrics_time ON gpu_metrics_history(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_gpu_metrics_worker_time ON gpu_metrics_history(worker_address, recorded_at DESC);

-- =====================================================
-- WORKER PERFORMANCE SCORES (Aggregated Metrics)
-- =====================================================

CREATE TABLE IF NOT EXISTS worker_performance_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_address TEXT NOT NULL UNIQUE,
    compute_score NUMERIC(10, 2) DEFAULT 100.0,
    reliability_score NUMERIC(10, 2) DEFAULT 100.0,
    speed_score NUMERIC(10, 2) DEFAULT 100.0,
    combined_score NUMERIC(10, 2) DEFAULT 100.0,
    jobs_sampled INTEGER DEFAULT 0,
    last_calculated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_perf_scores_address ON worker_performance_scores(worker_address);
CREATE INDEX IF NOT EXISTS idx_perf_scores_combined ON worker_performance_scores(combined_score DESC);

-- =====================================================
-- SLASHING EVENTS (For Fraud Proof Tracking)
-- =====================================================

CREATE TABLE IF NOT EXISTS slashing_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_address TEXT NOT NULL,
    job_id TEXT,
    slash_amount NUMERIC(78, 0) NOT NULL,
    slash_reason TEXT NOT NULL, -- 'invalid_proof', 'timeout', 'malicious_result', 'consensus_violation'
    evidence_hash TEXT,
    reporter_address TEXT,
    tx_hash TEXT,
    block_number BIGINT,
    slashed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_slashing_worker ON slashing_events(worker_address);
CREATE INDEX IF NOT EXISTS idx_slashing_time ON slashing_events(slashed_at DESC);
CREATE INDEX IF NOT EXISTS idx_slashing_reason ON slashing_events(slash_reason);

-- =====================================================
-- DASHBOARD CACHE TABLE (For Pre-computed Metrics)
-- =====================================================

CREATE TABLE IF NOT EXISTS dashboard_cache (
    cache_key TEXT PRIMARY KEY,
    cache_value JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cache_expires ON dashboard_cache(expires_at);

-- Function to clean expired cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_cache()
RETURNS void AS $$
BEGIN
    DELETE FROM dashboard_cache WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- ADD MISSING COLUMNS TO WORKERS TABLE
-- =====================================================

-- Add gpu_count and gpu_type columns if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workers' AND column_name = 'gpu_count'
    ) THEN
        ALTER TABLE workers ADD COLUMN gpu_count INTEGER DEFAULT 1;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workers' AND column_name = 'gpu_type'
    ) THEN
        ALTER TABLE workers ADD COLUMN gpu_type TEXT DEFAULT 'Unknown';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workers' AND column_name = 'uptime_percent'
    ) THEN
        ALTER TABLE workers ADD COLUMN uptime_percent NUMERIC(5, 2) DEFAULT 100.0;
    END IF;
END $$;

-- =====================================================
-- VIEWS FOR DASHBOARD QUERIES
-- =====================================================

-- Worker uptime summary (last 24 hours)
CREATE OR REPLACE VIEW v_worker_uptime_24h AS
SELECT
    worker_address,
    COUNT(*) as heartbeat_count,
    MAX(heartbeat_time) as last_heartbeat,
    CASE
        WHEN COUNT(*) >= 1440 THEN 100.0  -- Perfect uptime (1 heartbeat/minute)
        WHEN COUNT(*) >= 1008 THEN 70.0 + (COUNT(*) - 1008) * 30.0 / 432  -- 70-100%
        WHEN COUNT(*) >= 576 THEN 40.0 + (COUNT(*) - 576) * 30.0 / 432   -- 40-70%
        ELSE COUNT(*) * 40.0 / 576  -- 0-40%
    END as uptime_percent
FROM heartbeats
WHERE heartbeat_time > NOW() - INTERVAL '24 hours'
GROUP BY worker_address;

-- GPU utilization trends (hourly aggregates)
CREATE OR REPLACE VIEW v_gpu_utilization_hourly AS
SELECT
    worker_address,
    DATE_TRUNC('hour', recorded_at) as hour,
    AVG(compute_utilization) as avg_utilization,
    MAX(compute_utilization) as max_utilization,
    AVG(temperature_celsius) as avg_temperature,
    AVG(power_watts) as avg_power
FROM gpu_metrics_history
WHERE recorded_at > NOW() - INTERVAL '7 days'
GROUP BY worker_address, DATE_TRUNC('hour', recorded_at)
ORDER BY hour DESC;

-- Earnings summary view
CREATE OR REPLACE VIEW v_worker_earnings_summary AS
SELECT
    worker_address,
    SUM(amount) FILTER (WHERE claim_type = 'staking') as staking_rewards,
    SUM(amount) FILTER (WHERE claim_type = 'mining') as mining_rewards,
    SUM(amount) FILTER (WHERE claim_type = 'referral') as referral_rewards,
    SUM(amount) as total_claimed,
    COUNT(*) as total_claims,
    MAX(claim_time) as last_claim
FROM reward_claims
WHERE status = 'completed'
GROUP BY worker_address;

-- =====================================================
-- CLEANUP FUNCTIONS
-- =====================================================

-- Function to cleanup old heartbeats (keep 7 days)
CREATE OR REPLACE FUNCTION cleanup_old_heartbeats()
RETURNS void AS $$
BEGIN
    DELETE FROM heartbeats WHERE heartbeat_time < NOW() - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old GPU metrics (keep 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_gpu_metrics()
RETURNS void AS $$
BEGIN
    DELETE FROM gpu_metrics_history WHERE recorded_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- TRIGGERS FOR AUTOMATIC UPDATES
-- =====================================================

-- Update worker uptime when heartbeat received
CREATE OR REPLACE FUNCTION update_worker_on_heartbeat()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE workers
    SET
        last_heartbeat = NEW.heartbeat_time,
        status = 'active'
    WHERE address = NEW.worker_address;

    -- If worker doesn't exist, that's OK - they might not be registered yet
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_worker_heartbeat ON heartbeats;
CREATE TRIGGER trg_update_worker_heartbeat
    AFTER INSERT ON heartbeats
    FOR EACH ROW
    EXECUTE FUNCTION update_worker_on_heartbeat();

-- Log slashing events to blockchain_events for indexing
CREATE OR REPLACE FUNCTION log_slashing_event()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO blockchain_events (
        contract_address,
        contract_name,
        event_name,
        event_data,
        tx_hash,
        block_number
    ) VALUES (
        'internal',
        'SlashingTracker',
        'WorkerSlashed',
        jsonb_build_object(
            'worker_address', NEW.worker_address,
            'amount', NEW.slash_amount::text,
            'reason', NEW.slash_reason,
            'job_id', NEW.job_id
        ),
        COALESCE(NEW.tx_hash, 'internal_' || NEW.id::text),
        COALESCE(NEW.block_number, 0)
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_log_slashing ON slashing_events;
CREATE TRIGGER trg_log_slashing
    AFTER INSERT ON slashing_events
    FOR EACH ROW
    EXECUTE FUNCTION log_slashing_event();
