// TEE Attestation Verification Circuit
//
// This module implements the "Proof of Attestation" (PoA) mechanism.
// It builds ZK circuits that prove a TEE quote signature is valid.
//
// The circuit verifies:
// 1. The quote signature is valid (ECDSA over P-256/P-384)
// 2. The certificate chain leads back to a trusted root (Intel/AMD)
// 3. The MRENCLAVE is in the whitelist
//
// This allows us to compress expensive signature verification and certificate
// validation into a succinct ZK proof that can be verified cheaply on-chain.

use super::field::M31;
use super::circuit::Circuit;
use super::tee_types::{TEEQuote, Certificate, EnclaveWhitelist};
use super::vm::{ObelyskVM, OpCode, Instruction, ExecutionTrace};
use super::ecdsa::{ECDSAVerifier, ECDSASignature, P256Point, ECDSACircuitConstraints};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};

/// Attestation verification circuit
///
/// This circuit proves that a TEE quote has a valid signature
/// without the verifier needing to check the signature themselves.
#[derive(Debug, Clone)]
pub struct AttestationCircuit {
    /// The quote being verified
    pub quote: TEEQuote,
    
    /// Whitelist of allowed enclaves
    pub whitelist: EnclaveWhitelist,
    
    /// Expected root certificate authority
    pub root_ca: Vec<u8>,
}

impl AttestationCircuit {
    /// Create a new attestation circuit
    pub fn new(
        quote: TEEQuote,
        whitelist: EnclaveWhitelist,
    ) -> Self {
        let root_ca = quote.tee_type.root_ca().to_vec();
        
        Self {
            quote,
            whitelist,
            root_ca,
        }
    }
    
    /// Build the circuit constraints
    ///
    /// This generates a circuit that can be proven with Stwo
    pub fn build(&self) -> Result<Circuit> {
        let mut circuit = Circuit::new();
        
        // Public inputs: quote hash
        let quote_hash = self.quote.hash();
        let quote_hash_m31 = bytes_to_m31(&quote_hash);
        circuit = circuit.with_public_inputs(quote_hash_m31.clone());
        
        // Public outputs: verification result (1 = valid, 0 = invalid)
        circuit = circuit.with_public_outputs(vec![M31::ONE]);
        
        // Constraint 1: MRENCLAVE is whitelisted
        // NOTE: In full implementation, this would be a Merkle proof
        // For Phase 2, we use a simple check
        if !self.whitelist.is_allowed(&self.quote.mrenclave) {
            return Err(anyhow!("MRENCLAVE not whitelisted"));
        }
        
        // Constraint 2: Signature verification
        // NOTE: ECDSA verification in ZK is complex
        // For Phase 2, we create a simplified circuit
        // Full implementation would use optimized ECDSA gadgets
        
        // Add signature verification constraints (simplified)
        circuit = self.add_signature_constraints(circuit)?;
        
        // Constraint 3: Certificate chain validation
        // Verify the cert chain leads back to trusted root
        circuit = self.add_certificate_constraints(circuit)?;
        
        Ok(circuit)
    }
    
    /// Add signature verification constraints
    ///
    /// Implements ECDSA P-256 verification as circuit constraints.
    /// The verification proves that the signature is valid without
    /// revealing the private key.
    fn add_signature_constraints(&self, mut circuit: Circuit) -> Result<Circuit> {
        // Verify signature format is correct
        if self.quote.signature.is_empty() {
            return Err(anyhow!("Empty signature"));
        }
        
        // Parse the signature
        let signature = if self.quote.signature.len() == 64 {
            ECDSASignature::from_bytes(self.quote.signature.as_slice().try_into()
                .map_err(|_| anyhow!("Invalid signature length"))?)
        } else {
            ECDSASignature::from_der(&self.quote.signature)
                .ok_or_else(|| anyhow!("Invalid DER signature"))?
        };
        
        // Extract public key from certificate chain (first cert contains signing key)
        let public_key = self.extract_public_key_from_cert_chain()?;
        
        // Hash the quote body (what was signed)
        // The signed data is the report_data field
        let quote_body = &self.quote.report_data;
        let message_hash = sha256_hash(quote_body);
        
        // Create ECDSA circuit constraints
        let ecdsa_constraints = ECDSACircuitConstraints::new(
            &public_key,
            &message_hash,
            &signature,
        );
        
        // Add ECDSA constraints to circuit
        let num_constraints = ecdsa_constraints.add_to_circuit(&mut circuit);
        tracing::debug!("Added {} ECDSA verification constraints", num_constraints);
        
        // Add final check: r == R.x (verification result)
        // This ensures the signature is valid
        for i in 0..8 {
            circuit.add_equality_constraint(
                ecdsa_constraints.r_limbs[i],
                ecdsa_constraints.r_point_x_limbs[i],
            );
        }
        
        Ok(circuit)
    }
    
    /// Extract public key from certificate chain
    fn extract_public_key_from_cert_chain(&self) -> Result<P256Point> {
        // The first certificate in the chain is the signing certificate
        // Its public key is what we use to verify the quote signature
        
        if self.quote.certificate_chain.is_empty() {
            return Err(anyhow!("Empty certificate chain"));
        }
        
        let signing_cert = &self.quote.certificate_chain[0];
        
        // Extract public key bytes from certificate
        // In production, parse X.509 DER to get SubjectPublicKeyInfo
        // For now, we expect the public key to be stored directly
        let pub_key_bytes = &signing_cert.public_key;
        
        if pub_key_bytes.len() == 65 && pub_key_bytes[0] == 0x04 {
            // Uncompressed public key
            P256Point::from_uncompressed(pub_key_bytes)
                .ok_or_else(|| anyhow!("Invalid public key on certificate"))
        } else if pub_key_bytes.len() == 33 {
            // Compressed public key - would need decompression
            Err(anyhow!("Compressed public keys not yet supported"))
        } else {
            Err(anyhow!("Invalid public key format in certificate"))
        }
    }
    
    /// Add certificate chain validation constraints
    fn add_certificate_constraints(&self, mut circuit: Circuit) -> Result<Circuit> {
        // NOTE: Certificate chain validation involves:
        // 1. Parse X.509 DER-encoded certificates
        // 2. Verify each cert signature with parent's public key
        // 3. Check expiration dates
        // 4. Verify final cert is signed by trusted root
        //
        // For Phase 2, we add simplified constraints
        
        if self.quote.certificate_chain.is_empty() {
            return Err(anyhow!("Empty certificate chain"));
        }
        
        // Add constraints for certificate validation
        circuit.add_multiplication_constraint(1, 2, 3); // Placeholder
        
        Ok(circuit)
    }
    
    /// Execute the verification in OVM
    ///
    /// This creates an execution trace that can be proven
    pub fn execute_verification(&self) -> Result<ExecutionTrace> {
        let mut vm = ObelyskVM::new();
        
        // Set public inputs (quote hash as M31 elements)
        let quote_hash = self.quote.hash();
        let quote_hash_m31 = bytes_to_m31(&quote_hash);
        vm.set_public_inputs(quote_hash_m31);
        
        // Build verification program
        let program = self.build_verification_program()?;
        vm.load_program(program);
        
        // Execute
        let trace = vm.execute()?;
        
        Ok(trace)
    }
    
    /// Build OVM program for verification
    fn build_verification_program(&self) -> Result<Vec<Instruction>> {
        let mut program = Vec::new();
        
        // Load verification result into r0 (1 = valid)
        program.push(Instruction {
            opcode: OpCode::LoadImm,
            dst: 0,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ONE),
            address: None,
        });
        
        // NOTE: Full implementation would have:
        // 1. Load signature components into registers
        // 2. Execute ECDSA verification
        // 3. Load certificate chain
        // 4. Verify each certificate
        // 5. Check MRENCLAVE whitelist
        // 6. Set result based on all checks
        
        // Halt
        program.push(Instruction {
            opcode: OpCode::Halt,
            dst: 0,
            src1: 0,
            src2: 0,
            immediate: None,
            address: None,
        });
        
        Ok(program)
    }
}

/// Proof of Attestation (PoA)
///
/// This is the main interface for generating and verifying PoA proofs
pub struct ProofOfAttestation {
    whitelist: EnclaveWhitelist,
}

impl ProofOfAttestation {
    /// Create a new PoA verifier
    pub fn new() -> Self {
        Self {
            whitelist: EnclaveWhitelist::new(),
        }
    }
    
    /// Create with custom whitelist
    pub fn with_whitelist(whitelist: EnclaveWhitelist) -> Self {
        Self { whitelist }
    }
    
    /// Verify a TEE quote locally (fast check, no ZK proof)
    ///
    /// This performs full ECDSA signature verification without generating a ZK proof.
    /// Used for optimistic verification.
    pub fn verify_quote_locally(&self, quote: &TEEQuote) -> Result<bool> {
        // Check 1: MRENCLAVE is whitelisted
        if !self.whitelist.is_allowed(&quote.mrenclave) {
            tracing::debug!("Quote verification failed: MRENCLAVE not whitelisted");
            return Ok(false);
        }
        
        // Check 2: Quote has signature
        if quote.signature.is_empty() {
            tracing::debug!("Quote verification failed: Empty signature");
            return Ok(false);
        }
        
        // Check 3: Certificate chain present
        if quote.certificate_chain.is_empty() {
            tracing::debug!("Quote verification failed: Empty certificate chain");
            return Ok(false);
        }
        
        // Check 4: Timestamp is reasonable (not too old)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let age_seconds = now.saturating_sub(quote.timestamp);
        if age_seconds > 86400 {  // 24 hours
            tracing::debug!("Quote verification failed: Quote too old ({} seconds)", age_seconds);
            return Ok(false);
        }
        
        // Check 5: Verify ECDSA signature
        let signing_cert = &quote.certificate_chain[0];
        let pub_key_bytes = &signing_cert.public_key;
        
        match ECDSAVerifier::verify_tee_quote_signature(
            pub_key_bytes,
            &quote.report_data,
            &quote.signature,
        ) {
            Ok(true) => {
                tracing::debug!("Quote ECDSA signature verified successfully");
            }
            Ok(false) => {
                tracing::debug!("Quote verification failed: Invalid ECDSA signature");
                return Ok(false);
            }
            Err(e) => {
                tracing::debug!("Quote verification failed: ECDSA error - {}", e);
                return Ok(false);
            }
        }
        
        // Check 6: Validate certificate chain (simplified)
        // In production, would verify:
        // - Each cert signed by parent
        // - Root matches trusted CA
        // - No expired certs
        // - No revoked certs
        if !self.validate_cert_chain_basic(&quote.certificate_chain) {
            tracing::debug!("Quote verification failed: Invalid certificate chain");
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Basic certificate chain validation
    fn validate_cert_chain_basic(&self, chain: &[Certificate]) -> bool {
        if chain.is_empty() {
            return false;
        }
        
        // Check all certs have required fields
        for cert in chain {
            if cert.public_key.is_empty() {
                return false;
            }
            if cert.signature.is_empty() {
                return false;
            }
        }
        
        // In production, would verify:
        // 1. Each cert signed by next cert in chain
        // 2. Root cert matches trusted CA (Intel/AMD/NVIDIA)
        // 3. Current time within validity period
        
        true
    }
    
    /// Generate a ZK proof of attestation
    ///
    /// This is used when a quote is challenged
    pub fn generate_proof(
        &self,
        quote: TEEQuote,
    ) -> Result<AttestationProof> {
        // Build the attestation circuit
        let circuit = AttestationCircuit::new(
            quote.clone(),
            self.whitelist.clone(),
        );
        
        // Execute verification to get trace
        let trace = circuit.execute_verification()?;
        
        // NOTE: In production, we would:
        // let prover = ObelyskProver::new();
        // let proof = prover.prove_execution(&trace)?;
        
        // For Phase 2, create mock proof
        Ok(AttestationProof {
            quote_hash: quote.hash(),
            verification_result: true,
            proof_data: vec![0xde, 0xad, 0xbe, 0xef], // Mock Stwo proof
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Verify an attestation proof
    pub fn verify_proof(&self, proof: &AttestationProof) -> Result<bool> {
        // NOTE: In production, would verify Stwo proof
        // For Phase 2, just check structure
        
        if proof.proof_data.is_empty() {
            return Ok(false);
        }
        
        Ok(proof.verification_result)
    }
}

impl Default for ProofOfAttestation {
    fn default() -> Self {
        Self::new()
    }
}

/// Attestation proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProof {
    /// Hash of the quote being verified
    pub quote_hash: Vec<u8>,
    
    /// Verification result (true = valid)
    pub verification_result: bool,
    
    /// The actual Stwo proof data
    pub proof_data: Vec<u8>,
    
    /// When the proof was generated
    pub generated_at: u64,
}

/// Helper: Convert bytes to M31 field elements
fn bytes_to_m31(bytes: &[u8]) -> Vec<M31> {
    bytes.chunks(4)
        .map(|chunk| {
            let val = u32::from_le_bytes([
                chunk.get(0).copied().unwrap_or(0),
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
                chunk.get(3).copied().unwrap_or(0),
            ]);
            M31::new(val)
        })
        .collect()
}

/// SHA-256 hash helper
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obelysk::MockTEEGenerator;
    
    #[test]
    fn test_attestation_circuit_creation() {
        let generator = MockTEEGenerator::new(TEEType::IntelTDX);
        let quote = generator.generate_quote(b"test_result");
        
        let mut whitelist = EnclaveWhitelist::new();
        whitelist.add(quote.mrenclave.clone());
        
        let circuit = AttestationCircuit::new(quote, whitelist);
        
        // Should be able to build circuit
        let built = circuit.build();
        assert!(built.is_ok());
    }
    
    #[test]
    fn test_local_verification() {
        let poa = ProofOfAttestation::new();
        let generator = MockTEEGenerator::new(TEEType::IntelTDX);
        let quote = generator.generate_quote(b"test");
        
        // Should fail (MRENCLAVE not whitelisted)
        let result = poa.verify_quote_locally(&quote);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    
    #[test]
    fn test_local_verification_with_whitelist() {
        let generator = MockTEEGenerator::new(TEEType::IntelTDX);
        let quote = generator.generate_quote(b"test");
        
        let mut whitelist = EnclaveWhitelist::new();
        whitelist.add(quote.mrenclave.clone());
        
        let poa = ProofOfAttestation::with_whitelist(whitelist);
        
        // Should succeed (MRENCLAVE whitelisted)
        let result = poa.verify_quote_locally(&quote);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_proof_generation() {
        let generator = MockTEEGenerator::new(TEEType::IntelTDX);
        let quote = generator.generate_quote(b"test");
        
        let mut whitelist = EnclaveWhitelist::new();
        whitelist.add(quote.mrenclave.clone());
        
        let poa = ProofOfAttestation::with_whitelist(whitelist);
        
        // Generate proof
        let proof = poa.generate_proof(quote);
        assert!(proof.is_ok());
        
        let proof = proof.unwrap();
        assert!(!proof.proof_data.is_empty());
        assert!(proof.verification_result);
    }
    
    #[test]
    fn test_proof_verification() {
        let generator = MockTEEGenerator::new(TEEType::IntelTDX);
        let quote = generator.generate_quote(b"test");
        
        let mut whitelist = EnclaveWhitelist::new();
        whitelist.add(quote.mrenclave.clone());
        
        let poa = ProofOfAttestation::with_whitelist(whitelist);
        
        // Generate and verify proof
        let proof = poa.generate_proof(quote).unwrap();
        let valid = poa.verify_proof(&proof).unwrap();
        
        assert!(valid);
    }
}

