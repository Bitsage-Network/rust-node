# Starknet Contract ABIs

This directory contains Application Binary Interface (ABI) definitions for BitSage Network smart contracts deployed on Starknet.

## Contract ABIs

### FraudProof Contract
**File:** `fraud_proof.json`
**Address:** `0x5d5bc1565e4df7c61c811b0c494f1345fc0f964e154e57e829c727990116b50`

Key functions:
- `submit_challenge` - Submit a fraud proof challenge
- `resolve_challenge` - Resolve a challenge using verification
- `vote_on_challenge` - Vote on manual arbitration
- `get_challenge` - Query challenge details
- `get_stats` - Get contract statistics

### WorkerStaking Contract
**File:** `worker_staking.json`
**Address:** `0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613`

Key functions:
- `stake` - Stake SAGE tokens as a worker
- `get_stake` - Query worker stake information
- `get_min_stake` - Get minimum stake requirements
- `slash` - Slash malicious worker stake
- `get_worker_address` - Get worker's address

## How to Extract ABIs

### Method 1: Using starkli (Recommended)

```bash
# Install starkli
curl https://get.starkli.sh | sh
starkliup

# Extract ABI from deployed contract
starkli class-abi <CLASS_HASH> > contract_abi.json

# Class hashes from deployment:
# FraudProof: 0x7ed4704f130ec97247e747f3b53b12823723a6e9d84f373f1c6b3e6e06b6825
# WorkerStaking: 0x4028ef09e129ede97c196764ecde9b9672080dfe02b8e29b4e1140001cc967d
```

### Method 2: Using RPC Directly

```bash
curl -X POST https://rpc.starknet-testnet.lava.build \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "starknet_getClass",
    "params": ["0x<CLASS_HASH>"],
    "id": 1
  }' | jq '.result.abi'
```

### Method 3: From Source (Cairo Contracts)

```bash
# Navigate to Cairo contracts directory
cd ../BitSage-Cairo-Smart-Contracts

# Build contracts to generate ABIs
scarb build

# ABIs will be in target/dev/ directory
```

## Usage in Rust

The ABIs in this directory can be used with `starknet-rs` for type-safe contract interactions:

```rust
use starknet::core::types::FieldElement;
use starknet::core::utils::get_selector_from_name;
use starknet::accounts::Call;

// Create a call to submit_challenge
let selector = get_selector_from_name("submit_challenge")?;
let call = Call {
    to: fraud_proof_contract,
    selector,
    calldata: vec![
        job_id,
        worker_id,
        original_hash,
        disputed_hash,
        verification_method,
        evidence_hash,
    ],
};
```

## ABI Structure

Each ABI file contains:
- **functions** - Callable contract functions with inputs/outputs
- **structs** - Data structures used by the contract
- **events** - Events emitted by the contract (if any)

State mutability:
- `external` - Modifies state (requires transaction)
- `view` - Read-only (can be called for free)

## Contract Addresses

All contracts deployed on **Starknet Sepolia Testnet**:

| Contract | Address | Class Hash |
|----------|---------|------------|
| FraudProof | `0x5d5bc...116b50` | `0x7ed470...6b6825` |
| WorkerStaking | `0x28caa5...437613` | `0x4028ef...cc967d` |
| ValidatorRegistry | `0x431a8b...92f5d9` | `0x1941ba...8c96ec` |
| ProofVerifier | `0x17ada5...bebc8b` | `0x72d03c...7fa74a` |

**Explorer:** https://sepolia.starkscan.co

## Updating ABIs

When contracts are upgraded, update the ABIs:

1. Get the new class hash from the upgrade transaction
2. Extract the new ABI using one of the methods above
3. Update the corresponding JSON file in this directory
4. Test the integration with the new ABI

## Notes

- ABIs in this directory are simplified for the key functions used by the Rust node
- Full ABIs can be extracted from the deployed contracts using starkli
- Always verify contract addresses match your deployment before using
