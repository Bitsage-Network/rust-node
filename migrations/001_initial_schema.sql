-- =====================================================
-- BitSage Network - Initial Database Schema
-- Version: 1.0.0
-- Date: 2025-12-31
-- =====================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For text search

-- =====================================================
-- CORE TABLES
-- =====================================================

-- Jobs table (indexed from JobManager contract events)
CREATE TABLE jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id TEXT NOT NULL UNIQUE,
    client_address TEXT NOT NULL,
    worker_address TEXT,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    payment_amount NUMERIC(78, 0),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    assigned_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    execution_time_ms BIGINT,
    result_hash TEXT,
    error_message TEXT,
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_jobs_client ON jobs(client_address);
CREATE INDEX idx_jobs_worker ON jobs(worker_address);
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX idx_jobs_job_id_trgm ON jobs USING gin(job_id gin_trgm_ops);

-- Workers table (indexed from CDC Pool + Staking events)
CREATE TABLE workers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_id TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'inactive',
    staked_amount NUMERIC(78, 0) DEFAULT 0,
    gpu_tier TEXT,
    has_tee BOOLEAN DEFAULT FALSE,
    reputation_score INTEGER DEFAULT 100,
    jobs_completed BIGINT DEFAULT 0,
    jobs_failed BIGINT DEFAULT 0,
    total_earnings NUMERIC(78, 0) DEFAULT 0,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ,
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_workers_address ON workers(address);
CREATE INDEX idx_workers_status ON workers(status);
CREATE INDEX idx_workers_reputation ON workers(reputation_score DESC);
CREATE INDEX idx_workers_staked ON workers(staked_amount DESC);

-- Proofs table (indexed from ProofVerifier events)
CREATE TABLE proofs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    proof_hash TEXT NOT NULL,
    proof_type TEXT, -- 'stwo', 'stark', 'tee'
    circuit_type TEXT, -- 'AIInference', 'DataPipeline', etc.
    proof_size_bytes INTEGER,
    generation_time_ms INTEGER,
    security_bits INTEGER DEFAULT 128,
    is_valid BOOLEAN,
    verification_time_ms INTEGER,
    verified_at TIMESTAMPTZ,
    verifier_address TEXT,
    tx_hash TEXT,
    block_number BIGINT,
    CONSTRAINT fk_proof_job FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
);

CREATE INDEX idx_proofs_job ON proofs(job_id);
CREATE INDEX idx_proofs_worker ON proofs(worker_id);
CREATE INDEX idx_proofs_valid ON proofs(is_valid);
CREATE INDEX idx_proofs_verified ON proofs(verified_at DESC);

-- Staking events table
CREATE TABLE staking_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_id TEXT NOT NULL,
    worker_address TEXT NOT NULL,
    event_type TEXT NOT NULL, -- 'stake', 'unstake_initiated', 'unstake_completed', 'slashed', 'stake_increased'
    amount NUMERIC(78, 0) NOT NULL,
    gpu_tier TEXT,
    has_tee BOOLEAN,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT NOT NULL,
    block_number BIGINT NOT NULL
);

CREATE INDEX idx_staking_worker ON staking_events(worker_id);
CREATE INDEX idx_staking_address ON staking_events(worker_address);
CREATE INDEX idx_staking_type ON staking_events(event_type);
CREATE INDEX idx_staking_created ON staking_events(created_at DESC);

-- Payments/Earnings table
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id TEXT,
    worker_address TEXT NOT NULL,
    amount NUMERIC(78, 0) NOT NULL,
    payment_type TEXT NOT NULL, -- 'job_completion', 'stake_reward', 'referral', 'bonus'
    token TEXT DEFAULT 'SAGE',
    privacy_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT,
    CONSTRAINT fk_payment_job FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE SET NULL
);

CREATE INDEX idx_payments_worker ON payments(worker_address);
CREATE INDEX idx_payments_job ON payments(job_id);
CREATE INDEX idx_payments_created ON payments(created_at DESC);
CREATE INDEX idx_payments_type ON payments(payment_type);

-- =====================================================
-- TRADING TABLES (OTC Orderbook)
-- =====================================================

CREATE TABLE trading_pairs (
    id SERIAL PRIMARY KEY,
    pair_id INTEGER NOT NULL UNIQUE,
    base_token TEXT NOT NULL,
    quote_token TEXT NOT NULL,
    base_symbol TEXT NOT NULL DEFAULT 'SAGE',
    quote_symbol TEXT NOT NULL DEFAULT 'STRK',
    min_order_size NUMERIC(78, 0),
    tick_size NUMERIC(78, 0),
    maker_fee_bps INTEGER DEFAULT 25, -- 0.25%
    taker_fee_bps INTEGER DEFAULT 50, -- 0.50%
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT
);

CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id TEXT NOT NULL UNIQUE,
    pair_id INTEGER NOT NULL,
    maker_address TEXT NOT NULL,
    side TEXT NOT NULL, -- 'buy' or 'sell'
    order_type TEXT NOT NULL DEFAULT 'limit', -- 'limit' or 'market'
    price NUMERIC(78, 0),
    original_amount NUMERIC(78, 0) NOT NULL,
    filled_amount NUMERIC(78, 0) DEFAULT 0,
    remaining_amount NUMERIC(78, 0) NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- 'open', 'partial', 'filled', 'cancelled', 'expired'
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT,
    CONSTRAINT fk_order_pair FOREIGN KEY (pair_id) REFERENCES trading_pairs(pair_id)
);

CREATE INDEX idx_orders_pair ON orders(pair_id);
CREATE INDEX idx_orders_maker ON orders(maker_address);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_price ON orders(pair_id, side, price);
CREATE INDEX idx_orders_created ON orders(created_at DESC);
CREATE INDEX idx_orders_open ON orders(pair_id, status) WHERE status = 'open';

CREATE TABLE trades (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trade_id TEXT NOT NULL UNIQUE,
    pair_id INTEGER NOT NULL,
    maker_order_id TEXT NOT NULL,
    taker_order_id TEXT,
    maker_address TEXT NOT NULL,
    taker_address TEXT NOT NULL,
    side TEXT NOT NULL, -- From taker's perspective
    price NUMERIC(78, 0) NOT NULL,
    amount NUMERIC(78, 0) NOT NULL,
    quote_amount NUMERIC(78, 0) NOT NULL,
    maker_fee NUMERIC(78, 0),
    taker_fee NUMERIC(78, 0),
    executed_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_trades_pair ON trades(pair_id);
CREATE INDEX idx_trades_executed ON trades(executed_at DESC);
CREATE INDEX idx_trades_maker ON trades(maker_address);
CREATE INDEX idx_trades_taker ON trades(taker_address);

-- =====================================================
-- GOVERNANCE TABLES
-- =====================================================

CREATE TABLE proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id TEXT NOT NULL UNIQUE,
    proposer_address TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    proposal_type TEXT NOT NULL, -- 'parameter_change', 'treasury_spend', 'upgrade', 'emergency'
    status TEXT NOT NULL DEFAULT 'active', -- 'active', 'passed', 'rejected', 'executed', 'cancelled', 'expired'
    for_votes NUMERIC(78, 0) DEFAULT 0,
    against_votes NUMERIC(78, 0) DEFAULT 0,
    abstain_votes NUMERIC(78, 0) DEFAULT 0,
    quorum_required NUMERIC(78, 0),
    start_block BIGINT,
    end_block BIGINT,
    execution_payload TEXT, -- JSON encoded execution data
    created_at TIMESTAMPTZ DEFAULT NOW(),
    executed_at TIMESTAMPTZ,
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_proposals_status ON proposals(status);
CREATE INDEX idx_proposals_proposer ON proposals(proposer_address);
CREATE INDEX idx_proposals_created ON proposals(created_at DESC);

CREATE TABLE votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id TEXT NOT NULL,
    voter_address TEXT NOT NULL,
    support INTEGER NOT NULL, -- 0 = against, 1 = for, 2 = abstain
    voting_power NUMERIC(78, 0) NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT,
    UNIQUE(proposal_id, voter_address),
    CONSTRAINT fk_vote_proposal FOREIGN KEY (proposal_id) REFERENCES proposals(proposal_id) ON DELETE CASCADE
);

CREATE INDEX idx_votes_proposal ON votes(proposal_id);
CREATE INDEX idx_votes_voter ON votes(voter_address);

-- =====================================================
-- PRIVACY TABLES (Obelysk)
-- =====================================================

CREATE TABLE private_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address TEXT NOT NULL UNIQUE,
    public_key_x TEXT NOT NULL,
    public_key_y TEXT NOT NULL,
    stealth_meta_address TEXT,
    is_registered BOOLEAN DEFAULT TRUE,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_private_accounts_address ON private_accounts(address);

CREATE TABLE private_transfers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nullifier TEXT NOT NULL UNIQUE,
    sender_address TEXT,
    receiver_address TEXT,
    encrypted_amount TEXT,
    commitment TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'completed', 'failed'
    initiated_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_private_transfers_sender ON private_transfers(sender_address);
CREATE INDEX idx_private_transfers_receiver ON private_transfers(receiver_address);
CREATE INDEX idx_private_transfers_nullifier ON private_transfers(nullifier);
CREATE INDEX idx_private_transfers_status ON private_transfers(status);

CREATE TABLE stealth_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_address TEXT NOT NULL,
    stealth_address TEXT NOT NULL UNIQUE,
    ephemeral_pubkey TEXT NOT NULL,
    view_tag TEXT,
    is_spent BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    spent_at TIMESTAMPTZ,
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_stealth_owner ON stealth_addresses(owner_address);
CREATE INDEX idx_stealth_address ON stealth_addresses(stealth_address);

-- =====================================================
-- EVENT LOG (Raw blockchain events)
-- =====================================================

CREATE TABLE blockchain_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_address TEXT NOT NULL,
    contract_name TEXT, -- 'JobManager', 'Staking', etc.
    event_name TEXT NOT NULL,
    event_data JSONB NOT NULL,
    tx_hash TEXT NOT NULL,
    block_number BIGINT NOT NULL,
    block_timestamp TIMESTAMPTZ,
    log_index INTEGER,
    processed BOOLEAN DEFAULT FALSE,
    process_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_events_contract ON blockchain_events(contract_address);
CREATE INDEX idx_events_name ON blockchain_events(event_name);
CREATE INDEX idx_events_block ON blockchain_events(block_number);
CREATE INDEX idx_events_processed ON blockchain_events(processed) WHERE NOT processed;
CREATE INDEX idx_events_tx ON blockchain_events(tx_hash);

-- =====================================================
-- NETWORK STATS (Aggregated)
-- =====================================================

CREATE TABLE network_stats_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    total_workers INTEGER NOT NULL DEFAULT 0,
    active_workers INTEGER NOT NULL DEFAULT 0,
    total_jobs BIGINT NOT NULL DEFAULT 0,
    jobs_24h BIGINT NOT NULL DEFAULT 0,
    jobs_completed_24h BIGINT DEFAULT 0,
    total_staked NUMERIC(78, 0) NOT NULL DEFAULT 0,
    total_volume_24h NUMERIC(78, 0) DEFAULT 0,
    avg_job_time_ms BIGINT,
    network_utilization NUMERIC(5, 2),
    total_proofs_verified BIGINT DEFAULT 0,
    avg_proof_time_ms BIGINT,
    snapshot_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_stats_snapshot ON network_stats_snapshots(snapshot_at DESC);

-- =====================================================
-- REFERRAL SYSTEM
-- =====================================================

CREATE TABLE referrers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address TEXT NOT NULL UNIQUE,
    referral_code TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'bronze', -- 'bronze', 'silver', 'gold', 'diamond'
    commission_rate_bps INTEGER DEFAULT 500, -- 5% default
    total_referrals INTEGER DEFAULT 0,
    active_referrals INTEGER DEFAULT 0,
    total_volume NUMERIC(78, 0) DEFAULT 0,
    total_rewards NUMERIC(78, 0) DEFAULT 0,
    pending_rewards NUMERIC(78, 0) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT
);

CREATE INDEX idx_referrers_code ON referrers(referral_code);
CREATE INDEX idx_referrers_tier ON referrers(tier);

CREATE TABLE referrals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_address TEXT NOT NULL,
    referred_address TEXT NOT NULL UNIQUE,
    referral_code TEXT NOT NULL,
    volume_tracked NUMERIC(78, 0) DEFAULT 0,
    rewards_earned NUMERIC(78, 0) DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    block_number BIGINT,
    CONSTRAINT fk_referral_referrer FOREIGN KEY (referrer_address) REFERENCES referrers(address)
);

CREATE INDEX idx_referrals_referrer ON referrals(referrer_address);
CREATE INDEX idx_referrals_referred ON referrals(referred_address);

-- =====================================================
-- FAUCET CLAIMS
-- =====================================================

CREATE TABLE faucet_claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claimer_address TEXT NOT NULL,
    amount NUMERIC(78, 0) NOT NULL,
    claim_type TEXT DEFAULT 'standard', -- 'standard', 'social_task', 'bonus'
    claimed_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT NOT NULL,
    block_number BIGINT
);

CREATE INDEX idx_faucet_claimer ON faucet_claims(claimer_address);
CREATE INDEX idx_faucet_claimed ON faucet_claims(claimed_at DESC);

-- =====================================================
-- INDEXER STATE (Track sync progress)
-- =====================================================

CREATE TABLE indexer_state (
    id SERIAL PRIMARY KEY,
    contract_address TEXT NOT NULL UNIQUE,
    contract_name TEXT NOT NULL,
    last_indexed_block BIGINT NOT NULL DEFAULT 0,
    last_indexed_at TIMESTAMPTZ,
    is_syncing BOOLEAN DEFAULT FALSE,
    sync_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- VIEWS FOR COMMON QUERIES
-- =====================================================

-- Active order book view
CREATE VIEW v_orderbook AS
SELECT
    pair_id,
    side,
    price,
    SUM(remaining_amount) as total_amount,
    COUNT(*) as order_count
FROM orders
WHERE status = 'open' AND (expires_at IS NULL OR expires_at > NOW())
GROUP BY pair_id, side, price
ORDER BY pair_id, side, price;

-- Worker leaderboard view
CREATE VIEW v_worker_leaderboard AS
SELECT
    address,
    worker_id,
    staked_amount,
    reputation_score,
    jobs_completed,
    jobs_failed,
    total_earnings,
    CASE
        WHEN jobs_completed + jobs_failed > 0
        THEN ROUND(jobs_completed::numeric / (jobs_completed + jobs_failed) * 100, 2)
        ELSE 100
    END as success_rate
FROM workers
WHERE status = 'active'
ORDER BY reputation_score DESC, total_earnings DESC;

-- Daily stats view
CREATE VIEW v_daily_stats AS
SELECT
    DATE_TRUNC('day', created_at) as date,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_jobs,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_jobs,
    AVG(execution_time_ms) FILTER (WHERE status = 'completed') as avg_execution_time,
    SUM(payment_amount) FILTER (WHERE status = 'completed') as total_payments
FROM jobs
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', created_at)
ORDER BY date DESC;

-- =====================================================
-- FUNCTIONS
-- =====================================================

-- Function to update worker stats after job completion
CREATE OR REPLACE FUNCTION update_worker_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
        UPDATE workers
        SET
            jobs_completed = jobs_completed + 1,
            total_earnings = total_earnings + COALESCE(NEW.payment_amount, 0),
            last_heartbeat = NOW()
        WHERE address = NEW.worker_address;
    ELSIF NEW.status = 'failed' AND OLD.status != 'failed' THEN
        UPDATE workers
        SET
            jobs_failed = jobs_failed + 1,
            last_heartbeat = NOW()
        WHERE address = NEW.worker_address;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_worker_stats
    AFTER UPDATE ON jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_worker_stats();

-- Function to update order status
CREATE OR REPLACE FUNCTION update_order_status()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.filled_amount >= NEW.original_amount THEN
        NEW.status := 'filled';
        NEW.remaining_amount := 0;
    ELSIF NEW.filled_amount > 0 THEN
        NEW.status := 'partial';
        NEW.remaining_amount := NEW.original_amount - NEW.filled_amount;
    END IF;
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_order_status
    BEFORE UPDATE ON orders
    FOR EACH ROW
    EXECUTE FUNCTION update_order_status();

-- Function to update referrer stats
CREATE OR REPLACE FUNCTION update_referrer_stats()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE referrers
    SET
        total_referrals = total_referrals + 1,
        active_referrals = active_referrals + 1,
        updated_at = NOW()
    WHERE address = NEW.referrer_address;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_referrer_stats
    AFTER INSERT ON referrals
    FOR EACH ROW
    EXECUTE FUNCTION update_referrer_stats();

-- =====================================================
-- INITIAL DATA
-- =====================================================

-- Insert default trading pair (SAGE/STRK)
INSERT INTO trading_pairs (pair_id, base_token, quote_token, base_symbol, quote_symbol, min_order_size, maker_fee_bps, taker_fee_bps)
VALUES (
    0,
    '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850', -- SAGE
    '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d', -- STRK
    'SAGE',
    'STRK',
    1000000000000000000, -- 1 SAGE minimum
    25,  -- 0.25% maker fee
    50   -- 0.50% taker fee
);

-- Insert indexer state for all contracts
INSERT INTO indexer_state (contract_address, contract_name, last_indexed_block) VALUES
('0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3', 'JobManager', 0),
('0x1f978cad424f87a6cea8aa27cbcbba10b9a50d41e296ae07e1c635392a2339', 'CDCPool', 0),
('0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b', 'Staking', 0),
('0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b', 'ProofVerifier', 0),
('0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0', 'OTCOrderbook', 0),
('0xdf4c3ced8c8eafe33532965fe29081e6f94fb7d54bc976721985c647a7ef92', 'Governance', 0),
('0x7d1a6c242a4f0573696e117790f431fd60518a000b85fe5ee507456049ffc53', 'PrivacyRouter', 0),
('0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de', 'Reputation', 0),
('0x1d400338a38fca24e67c113bcecac4875ec1b85a00b14e4e541ed224fee59e4', 'Referral', 0),
('0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3', 'Faucet', 0);

-- Create initial network stats snapshot
INSERT INTO network_stats_snapshots (total_workers, active_workers, total_jobs, jobs_24h, total_staked)
VALUES (0, 0, 0, 0, 0);
