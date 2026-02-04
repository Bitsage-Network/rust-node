-- Migration 003: Add IP tracking to faucet_claims for persistent rate limiting
-- This enables IP-based cooldown that survives coordinator restarts

ALTER TABLE faucet_claims ADD COLUMN IF NOT EXISTS claimer_ip TEXT;

CREATE INDEX IF NOT EXISTS idx_faucet_claimer_ip ON faucet_claims(claimer_ip);
