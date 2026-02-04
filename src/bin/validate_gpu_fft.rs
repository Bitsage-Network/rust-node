/// GPU FFT Validation: Compares GPU vs SIMD FFT output element-by-element
/// to find the exact divergence point.

use stwo_prover::core::fields::m31::BaseField;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::prover::backend::simd::SimdBackend;
use stwo_prover::prover::backend::simd::column::BaseColumn;
use stwo_prover::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo_prover::prover::poly::BitReversedOrder;

#[cfg(feature = "cuda")]
use stwo_prover::prover::backend::gpu::GpuBackend;

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    println!("=== GPU vs SIMD FFT Validation ===\n");

    for log_size in [16u32, 17, 18] {
        validate_fft(log_size);
        validate_ifft(log_size);
    }
}

fn validate_fft(log_size: u32) {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();

    // Create deterministic test data
    let values: BaseColumn = (0..n)
        .map(|i| BaseField::from_u32_unchecked(((i * 7 + 3) % 2147483647) as u32))
        .collect();

    // SIMD path: interpolate (IFFT) then evaluate (FFT)
    let simd_eval = CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(
        domain, values.clone(),
    );
    let simd_twiddles = SimdBackend::precompute_twiddles(domain.half_coset);
    let simd_coeffs = SimdBackend::interpolate(simd_eval, &simd_twiddles);

    // Now evaluate the coefficients back on domain (this is the FFT direction)
    #[allow(unused_variables)]
    let simd_result = SimdBackend::evaluate(&simd_coeffs, domain, &simd_twiddles);

    // GPU path: same operations
    #[cfg(feature = "cuda")]
    {
        let gpu_eval = CircleEvaluation::<GpuBackend, BaseField, BitReversedOrder>::new(
            domain, values.clone(),
        );
        let gpu_twiddles = GpuBackend::precompute_twiddles(domain.half_coset);
        let gpu_coeffs = GpuBackend::interpolate(gpu_eval, &gpu_twiddles);

        // Compare interpolation (IFFT) results
        let simd_c = simd_coeffs.coeffs.as_slice();
        let gpu_c = gpu_coeffs.coeffs.as_slice();
        let mut ifft_mismatches = 0;
        let mut first_ifft_mismatch = None;
        for i in 0..n {
            if simd_c[i] != gpu_c[i] {
                if first_ifft_mismatch.is_none() {
                    first_ifft_mismatch = Some((i, simd_c[i], gpu_c[i]));
                }
                ifft_mismatches += 1;
            }
        }

        // Now evaluate (FFT)
        let gpu_result = GpuBackend::evaluate(&gpu_coeffs, domain, &gpu_twiddles);

        let simd_v = simd_result.values.as_slice();
        let gpu_v = gpu_result.values.as_slice();
        let mut fft_mismatches = 0;
        let mut first_fft_mismatch = None;
        for i in 0..n {
            if simd_v[i] != gpu_v[i] {
                if first_fft_mismatch.is_none() {
                    first_fft_mismatch = Some((i, simd_v[i], gpu_v[i]));
                }
                fft_mismatches += 1;
            }
        }

        let ifft_status = if ifft_mismatches == 0 { "PASS" } else { "FAIL" };
        let fft_status = if fft_mismatches == 0 { "PASS" } else { "FAIL" };

        println!(
            "log_size={:2}  IFFT: {} ({}/{} match)  FFT: {} ({}/{} match)",
            log_size,
            ifft_status, n - ifft_mismatches, n,
            fft_status, n - fft_mismatches, n,
        );

        if let Some((idx, expected, got)) = first_ifft_mismatch {
            println!("  IFFT first mismatch: idx={}, SIMD={}, GPU={}", idx, expected.0, got.0);
        }
        if let Some((idx, expected, got)) = first_fft_mismatch {
            println!("  FFT first mismatch: idx={}, SIMD={}, GPU={}", idx, expected.0, got.0);
        }
    }

    #[cfg(not(feature = "cuda"))]
    {
        println!("log_size={:2}  (CUDA not enabled, SIMD only)", log_size);
    }
}

fn validate_ifft(log_size: u32) {
    // Roundtrip test: values -> IFFT -> FFT should return original values
    let n = 1usize << log_size;
    #[allow(unused_variables)]
    let domain = CanonicCoset::new(log_size).circle_domain();

    #[allow(unused_variables)]
    let values: BaseColumn = (0..n)
        .map(|i| BaseField::from_u32_unchecked(((i * 13 + 5) % 2147483647) as u32))
        .collect();

    #[cfg(feature = "cuda")]
    {
        let eval = CircleEvaluation::<GpuBackend, BaseField, BitReversedOrder>::new(
            domain, values.clone(),
        );
        let twiddles = GpuBackend::precompute_twiddles(domain.half_coset);
        let coeffs = GpuBackend::interpolate(eval, &twiddles);
        let roundtrip = GpuBackend::evaluate(&coeffs, domain, &twiddles);

        let orig = values.as_slice();
        let rt = roundtrip.values.as_slice();
        let mut mismatches = 0;
        for i in 0..n {
            if orig[i] != rt[i] {
                mismatches += 1;
            }
        }

        let status = if mismatches == 0 { "PASS" } else { "FAIL" };
        println!(
            "log_size={:2}  Roundtrip: {} ({}/{} match)",
            log_size, status, n - mismatches, n,
        );
    }
}
