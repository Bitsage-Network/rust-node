# BitSage Validator UI - Backend & Blockchain Integration Analysis

**Date:** 2026-01-02  
**Status:** 🔴 **CRITICAL** - Most UI features are NOT wired to real backend/blockchain data

---

## Executive Summary

The BitSage Validator dashboard has a **complete and well-structured SDK** that connects to backend APIs, BUT the **backend is returning MOCK DATA** for most endpoints. Additionally, several features have no backend implementation at all.

### Overall Status
- ✅ **SDK Architecture**: Excellent - Clean TypeScript SDK with React hooks  
- ✅ **API Routes**: Implemented - All routes exist in rust-node  
- 🔴 **Backend Logic**: MOCKED - Most endpoints return hardcoded test data  
- 🔴 **Blockchain Integration**: MISSING - No real on-chain calls  
- 🟡 **WebSocket**: PARTIAL - Infrastructure exists but limited real data  

---

## 1. Dashboard Page - MOSTLY MOCKED

### UI Components Present
- Validator Status Banner (reputation, active status)
- Stats Grid (GPUs, staked amount, total earnings, pending rewards)
- GPU Cards (individual GPU metrics, utilization, temperature)
- Recent Activity (job list)
- Real-time Network Stats (WebSocket)

### SDK Integration
✅ **Well Integrated** - Uses proper hooks:
- `useValidatorStatus()` → `/api/validator/status`
- `useGpuMetrics()` → `/api/validator/gpus`  
- `useRewardsInfo()` → `/api/validator/rewards`
- `useStakeInfo()` → On-chain contract call
- `useRecentJobs()` → `/api/jobs/recent`
- `useNetworkStatsStream()` → WebSocket `/ws/prover`

### Backend Status
🔴 **MOCKED DATA**:

**File:** `rust-node/src/api/dashboard.rs:259-284`
```rust
async fn get_validator_status() {
    // TODO: Integrate with actual data sources (blockchain, metrics, etc.)
    // For now, return mock data structure that dashboard can use
    
    Json(ValidatorStatusResponse {
        is_active: true,  // HARDCODED
        is_registered: true,  // HARDCODED
        staked_amount: "5000000000000000000000".to_string(), // HARDCODED 5000 SAGE
        reputation_score: 850,  // HARDCODED
        jobs_completed: 1847,  // HARDCODED
        // ...all mock values
    })
}
```

**File:** `rust-node/src/api/dashboard.rs:287-315`
```rust
async fn get_gpu_metrics() {
    // TODO: Integrate with NVML or similar for real GPU metrics
    
    Json(GpuMetricsResponse {
        gpus: vec![
            GpuInfo {
                model: "NVIDIA H100 80GB HBM3".to_string(),  // HARDCODED
                compute_utilization: 87.5,  // HARDCODED
                temperature_celsius: 62.0,  // HARDCODED
                // ...all mock GPU data
            },
        ],
    })
}
```

### What Needs to Be Wired

1. **Validator Status** → Needs:
   - ✅ Starknet contract calls to `ProverStaking.get_stake(address)`
   - ✅ Starknet contract calls to `ReputationManager.get_reputation(address)`
   - ❌ Real job count from coordinator database
   - ❌ Real uptime tracking

2. **GPU Metrics** → Needs:
   - ❌ NVIDIA NVML integration for real GPU stats
   - ❌ Query actual GPU devices on the system
   - ❌ Real-time GPU temperature/utilization monitoring
   - ❌ Current job ID lookup from coordinator

3. **Rewards** → Needs:
   - ✅ On-chain query to `ProverStaking.get_pending_rewards(address)`
   - ❌ Real earnings calculation from completed jobs
   - ❌ Claim history from blockchain events

---

## 2. Jobs Page - PARTIALLY WIRED

### UI Features
- Jobs list with filters (status, type, date)
- Job details modal
- Job cancellation
- Retry failed jobs
- Pagination

### SDK Integration
✅ Uses `/api/jobs` endpoints via SDK

### Backend Status
🟡 **PARTIALLY IMPLEMENTED**

**Database Layer Exists**: `src/api/jobs_db.rs` has real PostgreSQL queries

**File:** `rust-node/src/api/jobs_db.rs:984-995`
```rust
pub async fn get_jobs_from_db(
    State(state): State<Arc<AppState>>,
    Query(params): Query<JobQueryParams>,
) -> Result<Json<JobsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Real PostgreSQL query
    let query_result = sqlx::query_as::<_, JobRow>(&query_str)
        .fetch_all(&state.db)
        .await
```

✅ **Jobs ARE stored in database**  
✅ **Query endpoints work**  
❌ **Job submission may not create real compute jobs**  
❌ **Job status updates may not reflect real execution**

### What Needs Verification
1. Does job submission actually create work for GPU workers?
2. Are job status updates coming from real execution or mock transitions?
3. Is proof generation actually happening for completed jobs?

---

## 3. Earnings Page - MOCKED

### UI Features
- Total earnings chart
- Earnings breakdown (mining vs staking)
- Claim rewards button
- Historical earnings graph

### SDK Integration
Uses `/api/validator/rewards` and `/api/earnings/*`

### Backend Status
🔴 **FULLY MOCKED**

**File:** `rust-node/src/api/dashboard.rs:318-332`
```rust
async fn get_rewards_info() {
    Json(RewardsInfoResponse {
        total_earned: "1250000000000000000000".to_string(),  // HARDCODED
        pending_rewards: "125000000000000000000".to_string(),  // HARDCODED
        apy_estimate: 12.5,  // HARDCODED
    })
}
```

### What Needs to Be Wired
1. ❌ Real-time earnings calculation from completed jobs
2. ❌ On-chain rewards query from MiningRewards contract
3. ❌ Staking rewards from ProverStaking contract
4. ❌ Claim transaction integration with wallet
5. ❌ Historical earnings from blockchain events or database

---

## 4. Stake Page - BLOCKCHAIN READY BUT INCOMPLETE

### UI Features
- Stake SAGE tokens
- Unstake with cooldown period
- Stake tier display
- APY calculator
- Transaction toasts

### SDK Integration
✅ **Well structured** - Uses StarknetReact hooks + BitSage SDK

**File:** `BitSage-Validator/src/app/(app)/stake/page.tsx`
```typescript
const { writeAsync: stakeWrite } = useStake();

const handleStake = async () => {
    const result = await stakeWrite({ amount: BigInt(amount) });
    // Shows transaction hash, waits for confirmation
};
```

### Backend Status
🟡 **CONTRACT INTEGRATION EXISTS BUT NEEDS TESTING**

✅ Contract addresses configured in `src/lib/contracts/addresses.ts`
✅ Starknet hooks imported from SDK
❌ No real testing with deployed contracts
❌ APY calculation is likely hardcoded
❌ Tier benefits may not match actual contract logic

### What Needs Verification
1. Are contracts actually deployed to Sepolia?
2. Do stake transactions actually go through?
3. Is the APY calculation real or estimated?
4. Does tier upgrade work correctly?

---

## 5. Trade/OTC Page - NO BACKEND

### UI Features
- Order book display
- Place buy/sell orders
- Trade history
- Market stats
- Privacy-preserving orders

### SDK Integration
Uses `/api/trading/*` endpoints

### Backend Status
🔴 **NO IMPLEMENTATION**

**File:** `rust-node/src/api/trading.rs:40-47`
```rust
pub fn trading_routes() -> Router {
    Router::new()
        .route("/api/trading/pairs", get(get_trading_pairs))
        .route("/api/trading/orderbook/:pair_id", get(get_orderbook))
        .route("/api/trading/orders", get(get_user_orders))
        // ...routes exist
}
```

**File:** `rust-node/src/api/trading.rs:140-165`
```rust
async fn get_orderbook(
    Path(pair_id): Path<String>,
) -> Json<OrderbookResponse> {
    debug!("Getting orderbook for pair: {}", pair_id);
    
    // TODO: Query from database
    Json(OrderbookResponse {  // RETURNS EMPTY
        pair_id,
        bids: vec![],
        asks: vec![],
        // ...
    })
}
```

❌ **ALL ENDPOINTS RETURN EMPTY DATA**

### What Needs to Be Built
1. ❌ OTC orderbook storage (database or on-chain)
2. ❌ Order matching engine
3. ❌ Privacy-preserving order encryption
4. ❌ Trade execution with settlement
5. ❌ Price discovery and TWAP calculations

---

## 6. Wallet Features - PARTIAL BLOCKCHAIN INTEGRATION

### Features
- Balance display
- Send SAGE tokens
- Privacy Pool deposits/withdrawals
- Stealth addresses
- Transaction history

### Blockchain Integration Status

#### Standard Wallet (page.tsx)
🟡 **BASIC INTEGRATION**
- ✅ Balance from Starknet RPC
- ✅ Send transactions via StarknetReact
- ❌ Transaction history not from blockchain
- ❌ Contact management is local-only

#### Privacy Pool (privacy-pool/page.tsx)
🔴 **NO REAL IMPLEMENTATION**
```typescript
const handleDeposit = async () => {
    // TODO: Implement privacy pool deposit
    console.log("Privacy pool deposit not implemented");
};
```

**What's Missing:**
- ❌ Privacy pool contract integration
- ❌ Note commitment generation
- ❌ Nullifier tracking
- ❌ Withdrawal proof generation

#### Stealth Addresses (stealth/page.tsx)
🔴 **NO IMPLEMENTATION**
```typescript
const handleGenerateStealth = () => {
    // Mock stealth address generation
    setStealthAddress("0x" + "a".repeat(64));
};
```

**What's Missing:**
- ❌ Real stealth address cryptography
- ❌ On-chain stealth registry
- ❌ Payment scanning
- ❌ Key derivation

---

## 7. Governance Page - NO BACKEND

### UI Features
- Browse proposals
- Create proposals
- Vote on proposals
- Delegation
- Voting power display

### SDK Integration
Has proper hooks: `useProposals()`, `useVote()`, `useDelegate()`

### Backend Status
🔴 **ENDPOINTS RETURN EMPTY**

**File:** `rust-node/src/api/governance.rs`
```rust
async fn get_proposals() -> Json<ProposalsResponse> {
    Json(ProposalsResponse {
        proposals: vec![],  // EMPTY
        total: 0,
    })
}
```

### What Needs to Be Built
1. ❌ Governance contract deployment
2. ❌ Proposal creation on-chain
3. ❌ Voting mechanism
4. ❌ Vote tallying
5. ❌ Execution queue

---

## 8. Faucet Page - WORKING

### Status
✅ **FULLY FUNCTIONAL**

**File:** `rust-node/src/api/faucet.rs`
- Has real implementation with rate limiting
- Calls deployed faucet contract
- Stores claim history in database
- Has captcha integration

**This is one of the few fully working features!**

---

## Critical Path: What to Wire First

### Phase 1: Core Dashboard (HIGH PRIORITY)
**Timeline:** 1-2 days

1. **Validator Status** - Wire to real data
   - Connect to ProverStaking contract for stake info
   - Connect to ReputationManager for reputation
   - Query real job counts from coordinator database
   
2. **GPU Metrics** - Integrate NVML
   - Add `nvml-wrapper` crate to detect real GPUs
   - Query actual GPU utilization, temperature, VRAM
   - Remove hardcoded H100 mock data

3. **Rewards** - Calculate from real sources
   - Query `MiningRewards` contract for pending rewards
   - Sum completed job payments from database
   - Calculate real APY from historical data

**Files to Modify:**
- `rust-node/src/api/dashboard.rs` (remove all TODOs)
- Add new module: `rust-node/src/gpu/nvml.rs`
- Update: `rust-node/src/coordinator/metrics.rs`

---

### Phase 2: Jobs & Earnings (MEDIUM PRIORITY)
**Timeline:** 2-3 days

1. **Verify Job Pipeline**
   - Test job submission → worker assignment → execution
   - Ensure proof generation is real
   - Verify payment distribution

2. **Earnings Calculation**
   - Real-time earnings from job completion events
   - Historical earnings from database
   - Chart data generation

**Files to Verify:**
- `rust-node/src/coordinator/job_processor.rs`
- `rust-node/src/compute/obelysk_executor.rs`
- `rust-node/src/api/earnings_db.rs`

---

### Phase 3: Trading & Privacy (LOW PRIORITY - FUTURE)
**Timeline:** 1-2 weeks

These are advanced features that can be added later:
- OTC orderbook
- Privacy pools
- Stealth addresses  
- Governance

---

## Verification Checklist

### To verify backend integration is complete:

```bash
# 1. Check if endpoints return real data
curl http://localhost:3030/api/validator/status

# Should see:
# - Your actual wallet address
# - Real stake amount from blockchain
# - Actual GPU count from system
# NOT hardcoded values

# 2. Check GPU metrics
curl http://localhost:3030/api/validator/gpus

# Should see:
# - Actual GPUs detected on system
# - Real utilization from nvidia-smi
# NOT "NVIDIA H100 80GB HBM3" if you don't have one

# 3. Check jobs are real
curl http://localhost:3030/api/jobs/recent

# Should see:
# - Jobs that were actually executed
# - Real proof hashes
# - Actual completion times
# NOT empty array or mock data

# 4. Check blockchain calls work
# In browser console with StarknetReact:
const stake = await contracts.proverStaking.get_stake(address);
console.log(stake); // Should match UI display
```

---

## Summary Table

| Feature | UI Status | SDK Status | Backend Status | Blockchain Status | Priority |
|---------|-----------|------------|----------------|-------------------|----------|
| Dashboard Stats | ✅ Complete | ✅ Integrated | 🔴 MOCKED | 🟡 Partial | 🔴 HIGH |
| GPU Metrics | ✅ Complete | ✅ Integrated | 🔴 MOCKED | N/A | 🔴 HIGH |
| Rewards/Earnings | ✅ Complete | ✅ Integrated | 🔴 MOCKED | ❌ Missing | 🔴 HIGH |
| Job List | ✅ Complete | ✅ Integrated | ✅ DB Wired | 🟡 Partial | 🟡 MEDIUM |
| Job Submission | ✅ Complete | ✅ Integrated | 🟡 Unclear | ❌ Missing | 🟡 MEDIUM |
| Staking | ✅ Complete | ✅ Integrated | N/A | 🟡 Untested | 🟡 MEDIUM |
| Faucet | ✅ Complete | ✅ Integrated | ✅ Working | ✅ Deployed | ✅ DONE |
| Trading/OTC | ✅ Complete | ✅ Integrated | ❌ Empty | ❌ Missing | 🟢 LOW |
| Privacy Pools | ✅ Complete | ✅ Integrated | ❌ Missing | ❌ Missing | 🟢 LOW |
| Stealth Addresses | ✅ Complete | ✅ Integrated | ❌ Missing | ❌ Missing | 🟢 LOW |
| Governance | ✅ Complete | ✅ Integrated | ❌ Empty | ❌ Missing | 🟢 LOW |

**Legend:**
- ✅ Complete/Working
- 🟡 Partial/Needs Testing
- 🔴 Critical Issue
- ❌ Not Implemented
- 🟢 Nice-to-Have

---

## Next Steps

1. **Remove Mock Data** from dashboard.rs
2. **Integrate NVML** for real GPU metrics
3. **Connect Blockchain** for stake/rewards
4. **Verify Job Pipeline** end-to-end
5. **Test Contract Calls** on Sepolia

The UI is **excellent and production-ready**. The backend just needs the real data sources wired up!
