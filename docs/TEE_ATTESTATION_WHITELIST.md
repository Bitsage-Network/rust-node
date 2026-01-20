# TEE Attestation Whitelist

## Overview

BitSage uses a **whitelist-based security model** for TEE attestations. Only worker enclaves with approved MRENCLAVE measurements can participate in the network. This prevents malicious or vulnerable code from processing sensitive computations.

---

## Security Model

### 1. MRENCLAVE Measurements

**MRENCLAVE** is a 256-bit hash (SHA-256) of the entire enclave contents:
- Code (executable binary)
- Data (initial memory state)
- Stack/heap layout
- Security flags

**Properties:**
- ✅ **Deterministic**: Same code → same MRENCLAVE
- ✅ **Tamper-proof**: Any code change → different MRENCLAVE
- ✅ **Hardware-attested**: Signed by CPU private key

### 2. Whitelist Structure

```rust
pub struct EnclaveVersion {
    mrenclave: Vec<u8>,          // 32-byte hash
    version: String,              // Semantic version (e.g., "1.0.0")
    description: String,          // Human-readable name
    whitelisted_at: u64,          // Unix timestamp
    deprecated_at: Option<u64>,   // Optional deprecation date
    revoked: bool,                // Emergency kill switch
    tee_type: TEEType,            // Intel TDX/SGX, AMD SEV-SNP
}
```

### 3. Version Lifecycle

```
Created → Active → Deprecated → Revoked
           ↓         ↓ (30-day grace)
        Workers   Workers must
        allowed   upgrade or be
                  removed
```

**States:**
1. **Active**: Current production version
2. **Deprecated**: Old version, allowed for 30 days
3. **Revoked**: Security vulnerability, immediately blocked

---

## Measuring MRENCLAVE

### Prerequisites

- Intel SGX-enabled CPU (or AMD SEV-SNP)
- Docker installed
- Gramine SGX runtime (for Intel)
- SGX driver and AESM service running

### Step 1: Build Worker Image

```bash
# Build Docker image
cd /Users/vaamx/bitsage-network/rust-node
docker build -f Dockerfile.worker -t bitsage-worker:v1.0.0 .

# Tag with version
docker tag bitsage-worker:v1.0.0 bitsage-worker:latest
```

### Step 2: Run in SGX (Intel)

```bash
# Create Gramine manifest
cat > sage-worker.manifest.template << 'MANIFEST'
loader.entrypoint = "file:{{ gramine.libos }}"
libos.entrypoint = "/app/sage-worker"

fs.mounts = [
  { path = "/lib", uri = "file:{{ gramine.runtimedir() }}" },
  { path = "/app", uri = "file:app" },
]

sgx.enclave_size = "1G"
sgx.thread_num = 32
sgx.debug = false

sgx.trusted_files = [
  "file:/app/sage-worker",
  "file:{{ gramine.runtimedir() }}/",
]
MANIFEST

# Generate SGX manifest
gramine-manifest \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    sage-worker.manifest.template \
    sage-worker.manifest

# Sign enclave
gramine-sgx-sign \
    --manifest sage-worker.manifest \
    --output sage-worker.manifest.sgx

# Extract MRENCLAVE from signature file
gramine-sgx-get-token --sig sage-worker.sig

# MRENCLAVE will be printed in the output
# Example: MRENCLAVE: a1b2c3d4e5f67890...
```

### Step 3: Run in TDX (Intel)

```bash
# TDX uses runtime measurement report (MRTD)
# Launch TD with worker image
td-shim --image bitsage-worker:v1.0.0 --measure

# Extract MRTD from attestation report
tdx-attest --report | jq -r '.mr_td'
```

### Step 4: Run in SEV-SNP (AMD)

```bash
# SEV-SNP uses launch measurement
qemu-system-x86_64 \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35,confidential-guest-support=sev0,memory-backend=ram1 \
    -object memory-backend-memfd-private,id=ram1,size=4G,share=true \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
    -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd \
    -drive file=bitsage-worker.qcow2,if=none,id=disk0,format=qcow2 \
    -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
    -device scsi-hd,drive=disk0,bootindex=0 \
    -nographic

# Inside VM, get attestation report
/opt/sev-guest/sev-guest-get-report report.bin

# Extract measurement
/opt/sev-guest/sev-guest-parse-report report.bin | grep MEASUREMENT
```

---

## Adding MRENCLAVE to Whitelist

### Option 1: Hardcoded (Development/Testnet)

Edit `src/obelysk/tee_types.rs`:

```rust
impl EnclaveWhitelist {
    pub fn new() -> Self {
        Self {
            versions: vec![
                EnclaveVersion {
                    mrenclave: hex::decode("a1b2c3d4e5f67890...")
                        .unwrap(),
                    version: "1.0.0".to_string(),
                    description: "BitSage Obelysk Worker v1.0.0".to_string(),
                    whitelisted_at: 1704067200,
                    deprecated_at: None,
                    revoked: false,
                    tee_type: TEEType::IntelTDX,
                },
            ],
        }
    }
}
```

### Option 2: Governance (Production)

```rust
// Smart contract call (Starknet)
let new_version = EnclaveVersion {
    mrenclave: hex::decode("a1b2c3d4...")?,
    version: "1.1.0".to_string(),
    description: "BitSage Worker v1.1.0 - Security patch".to_string(),
    whitelisted_at: current_timestamp(),
    deprecated_at: None,
    revoked: false,
    tee_type: TEEType::IntelTDX,
};

// Submit governance proposal
governance.propose_whitelist_update(new_version);

// Requires 67% DAO approval
// After approval, automatically added to whitelist
```

---

## Version Management

### Deprecate Old Version

```rust
let mut whitelist = EnclaveWhitelist::new();

// Deprecate v1.0.0 after releasing v1.1.0
let old_mrenclave = hex::decode("a1b2c3d4...")?.unwrap();
whitelist.deprecate_version(&old_mrenclave);

// Workers have 30 days to upgrade
// After grace period, workers with v1.0.0 are rejected
```

### Emergency Revocation

```rust
// Security vulnerability discovered in v1.0.5
let vulnerable_mrenclave = hex::decode("deadbeef...")?.unwrap();
whitelist.revoke_version(&vulnerable_mrenclave);

// IMMEDIATE effect: all workers with this version are blocked
// No grace period for revocations
```

---

## Verification Flow

### Worker Registration

```
1. Worker boots in TEE
2. TEE generates attestation quote
   - MRENCLAVE measurement
   - Report data (worker pubkey hash)
   - Hardware signature
3. Worker sends quote to coordinator
4. Coordinator checks whitelist:
   ✓ MRENCLAVE is in whitelist
   ✓ Version not deprecated/revoked
   ✓ Signature validates
   ✓ Certificate chain trusted
5. If valid: Worker registered
   If invalid: Registration rejected
```

### Runtime Verification

```
1. Coordinator assigns job to worker
2. Worker executes in TEE
3. Worker submits result + fresh attestation
4. Coordinator re-verifies:
   ✓ Same MRENCLAVE as registration
   ✓ Report data matches result hash
   ✓ Still whitelisted (not revoked)
5. If valid: Accept result + pay worker
   If invalid: Reject result + slash stake
```

---

## Governance Integration

### Proposal Types

1. **Add New Version**
   - Requires: Code review + security audit
   - Vote threshold: 67% approval
   - Effect: Immediate whitelist addition

2. **Deprecate Version**
   - Requires: Justification (bug fix, optimization)
   - Vote threshold: 51% approval
   - Effect: 30-day grace period

3. **Revoke Version**
   - Requires: Security vulnerability report
   - Vote threshold: Emergency multisig (3-of-5)
   - Effect: Immediate removal

### Governance Contract (Cairo)

```cairo
#[starknet::interface]
trait IEnclaveGovernance<TContractState> {
    fn propose_whitelist_addition(
        ref self: TContractState,
        mrenclave: felt252,
        version: felt252,
        description: Span<felt252>
    ) -> u256;  // proposal_id

    fn vote_proposal(ref self: TContractState, proposal_id: u256, vote: bool);

    fn execute_proposal(ref self: TContractState, proposal_id: u256);

    fn emergency_revoke(ref self: TContractState, mrenclave: felt252);
}
```

---

## Security Considerations

### Threat Model

**Attacker Goals:**
1. Run malicious code in worker enclave
2. Steal private keys or user data
3. Submit fake proofs

**Defenses:**
1. ✅ **Whitelist**: Only approved code can run
2. ✅ **Attestation**: Hardware proves code identity
3. ✅ **Versioning**: Track and deprecate vulnerable versions
4. ✅ **Revocation**: Emergency response to exploits

### Attack Scenarios

| Attack | Defense |
|--------|---------|
| Modified binary | Different MRENCLAVE → rejected |
| Replay old quote | Nonce in report_data → rejected |
| Side-channel leak | Constant-time crypto ops |
| Supply chain compromise | Reproducible builds + audits |

### Audit Checklist

- [ ] MRENCLAVE matches reproducible build
- [ ] No debug flags enabled (`sgx.debug = false`)
- [ ] Enclave size sufficient (`1G` minimum)
- [ ] All dependencies pinned (Cargo.lock)
- [ ] Code review completed
- [ ] Security audit passed
- [ ] Emergency revocation tested

---

## Monitoring & Alerts

### Metrics to Track

```rust
// Worker registration attempts
whitelist_check_total{result="allowed|rejected"}

// Version distribution
worker_version{version="1.0.0|1.1.0|..."}

// Deprecated version warnings
deprecated_version_usage{version="1.0.0", days_until_revocation="7"}
```

### Alerting Rules

```yaml
# Alert on high rejection rate
- alert: HighWhitelistRejectionRate
  expr: rate(whitelist_check_total{result="rejected"}[5m]) > 0.1
  for: 10m
  annotations:
    summary: "{{ $value }}% of workers rejected due to whitelist"

# Alert on deprecated version usage
- alert: DeprecatedVersionInUse
  expr: worker_version{version="1.0.0"} > 0 and days_until_revocation < 7
  annotations:
    summary: "{{ $value }} workers still on deprecated v1.0.0"
```

---

## Reproducible Builds

To ensure MRENCLAVE is deterministic:

```bash
# Use exact Rust version
rustup install 1.75.0
rustup default 1.75.0

# Pin all dependencies
cargo update
cargo vendor

# Build with reproducible flags
RUSTFLAGS="-C link-arg=-Wl,--build-id=none" \
cargo build --release --locked

# Verify MRENCLAVE matches published hash
gramine-sgx-sign --manifest sage-worker.manifest --output sage-worker.manifest.sgx
sha256sum sage-worker.manifest.sgx
# Should match: a1b2c3d4e5f67890...
```

---

## References

- [Intel SGX Developer Guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/)
- [AMD SEV-SNP Whitepaper](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [Gramine Documentation](https://gramine.readthedocs.io/)
- [Starknet Governance Contracts](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/governance/)

---

*Last Updated: 2026-01-01*  
*Version: 1.0.0*
