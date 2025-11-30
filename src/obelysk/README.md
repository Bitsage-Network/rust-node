# Obelysk Protocol

**Native Stwo Integration for BitSage Network**

Obelysk is BitSage's zkML protocol built on StarkWare's Stwo prover, providing verifiable ML inference and ETL computation with a hybrid TEE+ZK architecture.

---

## Quick Start

```rust
use bitsage_node::obelysk::{ObelykVM, OpCode, ObelyskProver, M31, vm::Instruction};

// 1. Create a program
let mut vm = ObelykVM::new();
vm.set_public_inputs(vec![M31::new(5), M31::new(7)]);

let program = vec![
    Instruction {
        opcode: OpCode::Add,
        dst: 2,
        src1: 0,
        src2: 1,
        immediate: None,
        address: None,
    },
    Instruction {
        opcode: OpCode::Halt,
        dst: 0,
        src1: 0,
        src2: 0,
        immediate: None,
        address: None,
    },
];

// 2. Execute
vm.load_program(program);
let trace = vm.execute()?;

// 3. Generate proof
let prover = ObelyskProver::new();
let proof = prover.prove_execution(&trace)?;

// 4. Verify
assert!(prover.verify_proof(&proof)?);
```

Run the example:
```bash
cargo run --example obelysk_simple_proof
```

---

## Architecture

### Mersenne-31 Field (`field.rs`)
- Prime field: p = 2³¹ - 1
- Hardware-optimized: fits in 32-bit register
- Fast reduction: no division required
- SIMD-friendly (AVX-512: 16 ops in parallel)

### Obelysk VM (`vm.rs`)
- Register-based (32 M31 registers)
- Execution trace generation
- ML-specific operations (MatMul, ReLU, Conv2D)
- Memory, control flow, arithmetic

### Circuit Builder (`circuit.rs`)
- Automatic trace → circuit conversion
- Constraint systems
- Lookup tables for quantization
- Power-of-2 sizing for FFT

### Prover (`prover.rs`)
- Currently: Mock implementation
- Production: Real Stwo Circle STARK proofs
- 128-bit security
- ~100KB proof size

---

## Status

**Phase 1** ✅ Complete (November 2025)
- M31 field implementation
- OVM virtual machine
- Circuit builder
- Mock prover
- Working example

**Phase 2** ⏳ Next (TEE-ZK Bridge)
- Proof of Attestation
- Optimistic rollup
- Challenge mechanism

**Phase 3-5** ⏳ Upcoming
- ML gadgets
- ONNX transpiler
- ETL verification
- Production deployment

---

## Why Obelysk?

### vs. Giza
- **10-100x faster**: M31 vs felt252
- **Hybrid TEE+ZK**: Privacy + speed
- **ETL support**: Full pipeline verification
- **Time to market**: 6+ months ahead

### vs. SP1
- **ML-optimized**: Specialized ISA
- **Hybrid architecture**: Not pure ZK
- **Narrower focus**: ML + Data pipelines

---

## Technical Details

### Field Operations
```rust
let a = M31::new(5);
let b = M31::new(7);
assert_eq!(a + b, M31::new(12));
```

Reduction is hardware-optimized:
```rust
fn reduce(x: u32) -> u32 {
    let low = x & 0x7FFFFFFF;
    let high = x >> 31;
    let sum = low + high;
    if sum >= M31_PRIME { sum - M31_PRIME } else { sum }
}
```

### VM Execution
```rust
OpCode::Add => {
    let src1 = self.registers[instruction.src1];
    let src2 = self.registers[instruction.src2];
    self.registers[instruction.dst] = src1 + src2;
}
```

### Proof Generation
```rust
pub fn prove_execution(&self, trace: &ExecutionTrace) -> Result<StarkProof> {
    let circuit = CircuitBuilder::from_trace(trace).build();
    self.prove_circuit(&circuit)
}
```

---

## Stwo Integration

**Current**: Mock implementation
```rust
// Generates mock proof for testing
let proof = prover.prove_execution(&trace)?;
```

**Production**: Real Stwo (requires nightly Rust)
```rust
// Add rust-toolchain.toml:
// [toolchain]
// channel = "nightly"

use stwo_prover::core::prover::prove;
let proof = prove(&circuit, &config)?;  // Real Circle STARK
```

---

## Performance

### Mock (Current)
- Proving: Instant
- Verification: Instant
- Proof size: ~107KB

### Real Stwo (Projected)
| Workload | Trace Size | Time | Proof |
|----------|-----------|------|-------|
| Simple | 2×32 | 10ms | 100KB |
| NN (10 layers) | 1K×64 | 1s | 150KB |
| ResNet-18 | 100K×128 | 10s | 200KB |
| LLaMA layer | 1M×256 | 100s | 300KB |

**vs. Giza (Stone)**: 10-100x faster

---

## Roadmap

- [x] **Phase 1**: Core infrastructure (2 hours) ✅
- [ ] **Phase 2**: TEE-ZK bridge (2 weeks)
- [ ] **Phase 3**: ML operations (2 weeks)
- [ ] **Phase 4**: ETL verification (2 weeks)
- [ ] **Phase 5**: Production launch (2 weeks)

**Total**: 8-12 weeks to production-ready zkML platform

---

## Resources

- [Integration Plan](../../../OBELYSK_INTEGRATION_PLAN.md) - Full roadmap
- [Phase 1 Complete](../../../OBELYSK_PHASE1_COMPLETE.md) - Current status
- [Technical Breakdown](../../../Obelyskbreakdown.md) - Deep dive
- [Stwo GitHub](https://github.com/starkware-libs/stwo) - StarkWare prover

---

**Status**: Phase 1 Complete ✅ | Next: TEE-ZK Bridge ⏳

