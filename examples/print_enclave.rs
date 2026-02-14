fn main() {
    let h = blake3::hash(b"bitsage-gpu-prover-v1-h100");
    let bytes = &h.as_bytes()[..31];
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    println!("enclave_measurement = 0x{}", hex);

    // Also compute as FieldElement
    use starknet::core::types::FieldElement;
    let fe = FieldElement::from_byte_slice_be(bytes).unwrap();
    println!("as FieldElement = {:#066x}", fe);
}
