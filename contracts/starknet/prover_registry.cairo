// =============================================================================
// BITSAGE PROVER REGISTRY - Starknet Smart Contract
// =============================================================================
//
// Inspired by Cocoon's RootContractConfig, adapted for ZK proof verification.
//
// This contract maintains:
// 1. Registry of allowed GPU prover image hashes (TEE measurements)
// 2. Registry of verified provers
// 3. Pricing configuration for proof generation
// 4. Proof verification integration with stwo-cairo-verifier
//
// =============================================================================

use starknet::ContractAddress;
use array::ArrayTrait;

// =============================================================================
// Data Types
// =============================================================================

/// TEE attestation data (TDX/SEV-SNP measurements)
#[derive(Drop, Serde, starknet::Store)]
struct TeeAttestation {
    /// MRTD - Measurement of initial TD contents (48 bytes as 6 felt252)
    mrtd: Array<felt252>,
    /// Image hash of the prover binary (32 bytes as 4 felt252)
    image_hash: Array<felt252>,
    /// TEE type: 0 = Intel TDX, 1 = AMD SEV-SNP, 2 = NVIDIA H100 CC
    tee_type: u8,
    /// Timestamp of attestation
    timestamp: u64,
}

/// Registered prover information
#[derive(Drop, Serde, starknet::Store)]
struct ProverInfo {
    /// Prover's Starknet address
    address: ContractAddress,
    /// GPU type: 0 = H100, 1 = A100, 2 = RTX4090, etc.
    gpu_type: u8,
    /// Number of GPUs
    gpu_count: u8,
    /// TEE attestation
    attestation: TeeAttestation,
    /// Reputation score (0-10000, basis points)
    reputation: u16,
    /// Total proofs generated
    proofs_generated: u64,
    /// Is currently active
    is_active: bool,
    /// Stake amount in STRK
    stake: u256,
}

/// Pricing configuration
#[derive(Drop, Serde, starknet::Store)]
struct PricingConfig {
    /// Base price per proof in STRK (18 decimals)
    base_price_per_proof: u256,
    /// Price multiplier for larger proofs (basis points, 10000 = 1x)
    size_multiplier: u16,
    /// Platform fee (basis points, e.g., 500 = 5%)
    platform_fee_bps: u16,
    /// Minimum stake required for provers
    min_stake: u256,
}

// =============================================================================
// Storage
// =============================================================================

#[starknet::interface]
trait IProverRegistry<TContractState> {
    // === Admin Functions ===
    fn add_allowed_image_hash(ref self: TContractState, image_hash: Array<felt252>);
    fn remove_allowed_image_hash(ref self: TContractState, image_hash: Array<felt252>);
    fn update_pricing(ref self: TContractState, config: PricingConfig);
    fn set_verifier_address(ref self: TContractState, verifier: ContractAddress);
    
    // === Prover Functions ===
    fn register_prover(
        ref self: TContractState,
        gpu_type: u8,
        gpu_count: u8,
        attestation: TeeAttestation,
    );
    fn deregister_prover(ref self: TContractState);
    fn update_attestation(ref self: TContractState, attestation: TeeAttestation);
    fn stake(ref self: TContractState, amount: u256);
    fn unstake(ref self: TContractState, amount: u256);
    
    // === Client Functions ===
    fn submit_proof_request(
        ref self: TContractState,
        proof_size_log: u8,
        max_price: u256,
    ) -> u256; // Returns request_id
    
    fn submit_proof(
        ref self: TContractState,
        request_id: u256,
        proof: Array<felt252>,
    );
    
    // === View Functions ===
    fn is_image_hash_allowed(self: @TContractState, image_hash: Array<felt252>) -> bool;
    fn get_prover_info(self: @TContractState, prover: ContractAddress) -> ProverInfo;
    fn get_pricing(self: @TContractState) -> PricingConfig;
    fn get_proof_price(self: @TContractState, proof_size_log: u8) -> u256;
    fn get_active_provers(self: @TContractState) -> Array<ContractAddress>;
    fn get_verifier_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
mod ProverRegistry {
    use super::{TeeAttestation, ProverInfo, PricingConfig, IProverRegistry};
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };
    use array::ArrayTrait;
    use option::OptionTrait;
    use traits::Into;

    // =========================================================================
    // Storage
    // =========================================================================
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        
        /// Allowed image hashes (hash -> is_allowed)
        allowed_image_hashes: Map<felt252, bool>,
        
        /// Registered provers (address -> info)
        provers: Map<ContractAddress, ProverInfo>,
        
        /// Active prover list
        active_prover_count: u32,
        active_provers: Map<u32, ContractAddress>,
        
        /// Pricing configuration
        pricing: PricingConfig,
        
        /// stwo-cairo-verifier contract address
        verifier_address: ContractAddress,
        
        /// Proof requests
        next_request_id: u256,
        proof_requests: Map<u256, ProofRequest>,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct ProofRequest {
        client: ContractAddress,
        proof_size_log: u8,
        price: u256,
        assigned_prover: ContractAddress,
        status: u8, // 0 = pending, 1 = assigned, 2 = completed, 3 = failed
        created_at: u64,
    }

    // =========================================================================
    // Events
    // =========================================================================
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ImageHashAdded: ImageHashAdded,
        ImageHashRemoved: ImageHashRemoved,
        ProverRegistered: ProverRegistered,
        ProverDeregistered: ProverDeregistered,
        ProofRequested: ProofRequested,
        ProofSubmitted: ProofSubmitted,
        ProofVerified: ProofVerified,
    }

    #[derive(Drop, starknet::Event)]
    struct ImageHashAdded {
        #[key]
        hash_prefix: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ImageHashRemoved {
        #[key]
        hash_prefix: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ProverRegistered {
        #[key]
        prover: ContractAddress,
        gpu_type: u8,
        gpu_count: u8,
    }

    #[derive(Drop, starknet::Event)]
    struct ProverDeregistered {
        #[key]
        prover: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofRequested {
        #[key]
        request_id: u256,
        client: ContractAddress,
        proof_size_log: u8,
        price: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofSubmitted {
        #[key]
        request_id: u256,
        prover: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofVerified {
        #[key]
        request_id: u256,
        success: bool,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        verifier: ContractAddress,
    ) {
        self.owner.write(owner);
        self.verifier_address.write(verifier);
        self.next_request_id.write(1);
        
        // Default pricing
        self.pricing.write(PricingConfig {
            base_price_per_proof: 100000000000000000_u256, // 0.1 STRK
            size_multiplier: 10000, // 1x base
            platform_fee_bps: 500,  // 5%
            min_stake: 1000000000000000000000_u256, // 1000 STRK
        });
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    #[abi(embed_v0)]
    impl ProverRegistryImpl of IProverRegistry<ContractState> {
        // === Admin Functions ===
        
        fn add_allowed_image_hash(ref self: ContractState, image_hash: Array<felt252>) {
            self._only_owner();
            let hash_key = *image_hash.at(0); // Use first felt as key
            self.allowed_image_hashes.write(hash_key, true);
            self.emit(ImageHashAdded { hash_prefix: hash_key });
        }

        fn remove_allowed_image_hash(ref self: ContractState, image_hash: Array<felt252>) {
            self._only_owner();
            let hash_key = *image_hash.at(0);
            self.allowed_image_hashes.write(hash_key, false);
            self.emit(ImageHashRemoved { hash_prefix: hash_key });
        }

        fn update_pricing(ref self: ContractState, config: PricingConfig) {
            self._only_owner();
            self.pricing.write(config);
        }

        fn set_verifier_address(ref self: ContractState, verifier: ContractAddress) {
            self._only_owner();
            self.verifier_address.write(verifier);
        }

        // === Prover Functions ===
        
        fn register_prover(
            ref self: ContractState,
            gpu_type: u8,
            gpu_count: u8,
            attestation: TeeAttestation,
        ) {
            let caller = get_caller_address();
            
            // Verify attestation image hash is allowed
            let hash_key = *attestation.image_hash.at(0);
            assert(self.allowed_image_hashes.read(hash_key), 'Image hash not allowed');
            
            // Create prover info
            let prover_info = ProverInfo {
                address: caller,
                gpu_type,
                gpu_count,
                attestation,
                reputation: 5000, // Start at 50%
                proofs_generated: 0,
                is_active: true,
                stake: 0_u256,
            };
            
            self.provers.write(caller, prover_info);
            
            // Add to active list
            let idx = self.active_prover_count.read();
            self.active_provers.write(idx, caller);
            self.active_prover_count.write(idx + 1);
            
            self.emit(ProverRegistered { prover: caller, gpu_type, gpu_count });
        }

        fn deregister_prover(ref self: ContractState) {
            let caller = get_caller_address();
            let mut info = self.provers.read(caller);
            info.is_active = false;
            self.provers.write(caller, info);
            self.emit(ProverDeregistered { prover: caller });
        }

        fn update_attestation(ref self: ContractState, attestation: TeeAttestation) {
            let caller = get_caller_address();
            
            // Verify new attestation is allowed
            let hash_key = *attestation.image_hash.at(0);
            assert(self.allowed_image_hashes.read(hash_key), 'Image hash not allowed');
            
            let mut info = self.provers.read(caller);
            info.attestation = attestation;
            self.provers.write(caller, info);
        }

        fn stake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let mut info = self.provers.read(caller);
            info.stake = info.stake + amount;
            self.provers.write(caller, info);
            // TODO: Transfer STRK tokens to contract
        }

        fn unstake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let mut info = self.provers.read(caller);
            assert(info.stake >= amount, 'Insufficient stake');
            info.stake = info.stake - amount;
            self.provers.write(caller, info);
            // TODO: Transfer STRK tokens back to prover
        }

        // === Client Functions ===
        
        fn submit_proof_request(
            ref self: ContractState,
            proof_size_log: u8,
            max_price: u256,
        ) -> u256 {
            let caller = get_caller_address();
            let price = self.get_proof_price(proof_size_log);
            assert(price <= max_price, 'Price exceeds max');
            
            let request_id = self.next_request_id.read();
            self.next_request_id.write(request_id + 1);
            
            let request = ProofRequest {
                client: caller,
                proof_size_log,
                price,
                assigned_prover: starknet::contract_address_const::<0>(),
                status: 0,
                created_at: get_block_timestamp(),
            };
            
            self.proof_requests.write(request_id, request);
            
            self.emit(ProofRequested { request_id, client: caller, proof_size_log, price });
            
            request_id
        }

        fn submit_proof(
            ref self: ContractState,
            request_id: u256,
            proof: Array<felt252>,
        ) {
            let caller = get_caller_address();
            let mut request = self.proof_requests.read(request_id);
            
            assert(request.status == 0 || request.status == 1, 'Invalid request status');
            
            // Verify prover is registered and staked
            let prover_info = self.provers.read(caller);
            assert(prover_info.is_active, 'Prover not active');
            
            let pricing = self.pricing.read();
            assert(prover_info.stake >= pricing.min_stake, 'Insufficient stake');
            
            // TODO: Call stwo-cairo-verifier to verify proof
            // let verifier = self.verifier_address.read();
            // IStwoVerifier::verify(verifier, proof);
            
            // Update request
            request.assigned_prover = caller;
            request.status = 2; // completed
            self.proof_requests.write(request_id, request);
            
            // Update prover stats
            let mut info = self.provers.read(caller);
            info.proofs_generated = info.proofs_generated + 1;
            self.provers.write(caller, info);
            
            self.emit(ProofSubmitted { request_id, prover: caller });
            self.emit(ProofVerified { request_id, success: true });
        }

        // === View Functions ===
        
        fn is_image_hash_allowed(self: @ContractState, image_hash: Array<felt252>) -> bool {
            let hash_key = *image_hash.at(0);
            self.allowed_image_hashes.read(hash_key)
        }

        fn get_prover_info(self: @ContractState, prover: ContractAddress) -> ProverInfo {
            self.provers.read(prover)
        }

        fn get_pricing(self: @ContractState) -> PricingConfig {
            self.pricing.read()
        }

        fn get_proof_price(self: @ContractState, proof_size_log: u8) -> u256 {
            let pricing = self.pricing.read();
            let base = pricing.base_price_per_proof;
            
            // Price scales with proof size: 2^(log-16) multiplier for log > 16
            let size_factor: u256 = if proof_size_log > 16 {
                let shift: u256 = (proof_size_log - 16).into();
                shift + 1
            } else {
                1_u256
            };
            
            base * size_factor
        }

        fn get_active_provers(self: @ContractState) -> Array<ContractAddress> {
            let count = self.active_prover_count.read();
            let mut provers: Array<ContractAddress> = ArrayTrait::new();
            
            let mut i: u32 = 0;
            loop {
                if i >= count {
                    break;
                }
                let addr = self.active_provers.read(i);
                let info = self.provers.read(addr);
                if info.is_active {
                    provers.append(addr);
                }
                i += 1;
            };
            
            provers
        }

        fn get_verifier_address(self: @ContractState) -> ContractAddress {
            self.verifier_address.read()
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn _only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'Only owner');
        }
    }
}

