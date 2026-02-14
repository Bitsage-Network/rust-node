-- Social task completions for faucet bonus token distribution
-- Tracks which wallet completed which social task (GitHub star, follow, etc.)

CREATE TABLE IF NOT EXISTS social_task_completions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address TEXT NOT NULL,
    task_id TEXT NOT NULL,           -- 'github_follow', 'github_star_stwo', etc.
    platform TEXT NOT NULL,          -- 'github', 'twitter', 'discord'
    task_type TEXT NOT NULL,         -- 'github_follow', 'github_star', 'twitter_follow', 'discord_join'
    reward_amount NUMERIC(78, 0) NOT NULL,
    completed_at TIMESTAMPTZ DEFAULT NOW(),
    tx_hash TEXT,
    social_account TEXT,             -- GitHub login, Twitter handle, etc.
    UNIQUE(wallet_address, task_id)  -- one completion per wallet per task
);

CREATE INDEX IF NOT EXISTS idx_social_tasks_wallet ON social_task_completions(wallet_address);
