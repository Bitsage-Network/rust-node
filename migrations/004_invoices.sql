CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_wallet TEXT NOT NULL,
    job_type TEXT NOT NULL,
    circuit_type TEXT,
    total_cost_cents BIGINT NOT NULL DEFAULT 0,
    worker_payment_cents BIGINT NOT NULL DEFAULT 0,
    protocol_fee_cents BIGINT NOT NULL DEFAULT 0,
    sage_to_worker BIGINT NOT NULL DEFAULT 0,
    gpu_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    gpu_model TEXT,
    proof_hash TEXT,
    proof_size_bytes BIGINT,
    proof_time_ms BIGINT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(job_id, worker_id)
);
CREATE INDEX IF NOT EXISTS idx_invoices_job_id ON invoices(job_id);
CREATE INDEX IF NOT EXISTS idx_invoices_worker ON invoices(worker_id);
