use ff_ext::GoldilocksExt2;
use p3_field::PrimeCharacteristicRing;

use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::Field;
use plonky2::field::types::Field64;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::{log2_ceil, log2_strict};
use rayon::prelude::*;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type E = GoldilocksExt2;

pub fn barycentric_evaluation(mut image: Vec<u8>, eval_point: F) -> F {
    // Using formula at the bottom of this page: https://hackmd.io/@vbuterin/barycentric_evaluation
    // Degree is N in that formula
    let degree = image.len().next_power_of_two();
    // while image.len() < degree {
    //     image.push(0_u8);
    // }
    let degree_bits = log2_strict(degree);
    let omega = F::primitive_root_of_unity(degree_bits);
    // Will contain powers of omega needed for sum
    let mut omega_acc = F::ONE;
    // Running sum:
    let mut sum: GoldilocksField = F::ZERO;
    static MONTGOMERY_STEP_SIZE: usize = 512;
    let mut numerators = vec![F::ZERO; MONTGOMERY_STEP_SIZE];
    let mut denominators = vec![F::ZERO; MONTGOMERY_STEP_SIZE];
    let mut montgomery_partial_prods = vec![F::ZERO; MONTGOMERY_STEP_SIZE];
    for i in (0..image.len()).step_by(MONTGOMERY_STEP_SIZE) {
        for j in 0..MONTGOMERY_STEP_SIZE {
            numerators[j] = F::from_canonical_u8(image[i + j]) * omega_acc;
            denominators[j] = eval_point - omega_acc;
            montgomery_partial_prods[j] = if j == 0 {
                denominators[j]
            } else {
                denominators[j] * montgomery_partial_prods[j - 1]
            };
            omega_acc *= omega;
        }

        let mut last_inverse = montgomery_partial_prods[MONTGOMERY_STEP_SIZE - 1].inverse();
        for j in (1..MONTGOMERY_STEP_SIZE).rev() {
            let inverted_denominator = montgomery_partial_prods[j - 1] * last_inverse;
            sum += inverted_denominator * numerators[j];
            last_inverse *= denominators[j];
        }
        sum += last_inverse * numerators[0];
    }
    let front_quantity =
        (eval_point.exp_u64(degree as u64) - F::ONE) / F::from_canonical_u64(degree as u64);

    front_quantity * sum
}

pub fn horners_evaluation(mut image: Vec<u8>, eval_point: F) -> F {
    let mut sum: GoldilocksField = F::ZERO;
    for i in (0..image.len()) {
        sum *= eval_point;
        sum += F::from_canonical_u8(image[i]);
    }

    sum
}

pub fn perform_ifft(mut unpadded_evals: Vec<u8>) -> PolynomialCoeffs<F> {
    let degree = unpadded_evals.len().next_power_of_two();
    while unpadded_evals.len() < degree {
        unpadded_evals.push(0_u8);
    }
    let vals = PolynomialValues::from(
        unpadded_evals
            .iter()
            .map(|n| F::from_canonical_u8(*n))
            .collect::<Vec<F>>(),
    );
    vals.ifft()
}

pub fn ifft_evaluation(mut image: Vec<u8>, eval_point: F) -> F {
    let ifft = perform_ifft(image);
    ifft.eval(eval_point)
}

pub fn random_felt(x1: u64) -> F {
    F::from_canonical_u64(x1)
}

pub fn random_felt_ceno(x1: u64) -> E {
    E::from_u64(x1)
}

pub fn image_merkle_tree(image: Vec<u8>, chunk_size: usize) -> MerkleTree<Sha256> {
    let mut leaves = Vec::new();

    // Process image in 32-byte chunks
    for chunk in image.chunks(chunk_size) {
        leaves.push(Sha256::hash(chunk));
    }

    // Construct and return the Merkle tree
    MerkleTree::<Sha256>::from_leaves(&leaves)
}

pub fn compute_video_mle_evaluations_vec(
    pixels: &[u64],
    frame_size: usize,
    num_frames: usize,
) -> Vec<E> {
    assert!(
        frame_size * num_frames == pixels.len(),
        "Pixels is of an unexpected size!"
    );
    let frame_size_padded = frame_size.next_power_of_two();
    let num_frames_padded = num_frames.next_power_of_two();
    let video_size = num_frames * frame_size;
    let poly_size = num_frames_padded * frame_size_padded;

    let mut evaluations = Vec::with_capacity(poly_size);
    for i in 0..num_frames.next_power_of_two() {
        for j in 0..frame_size.next_power_of_two() {
            if i < num_frames && j < frame_size {
                evaluations.push(E::from_u64(pixels[i * frame_size + j]));
            } else {
                evaluations.push(E::from_u64(0));
            }
        }
    }
    evaluations
}
