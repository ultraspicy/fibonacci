// This file benchmarks the work the a signer would need to do to validate an outsourced signature.
// In our setup, these are the different steps a camera would be doing.
// We don't include the time to sign a value, we just include the time to hash/or validate that a
// PCS is correctly produced.
// We benchmark the following approaches:
// - Merkle Hashing with SHA-256 (base case for redactable signatures)
// - Merkle Hashing with SHA-256, leaves are frames (more reasonable base case since we only reveal a frame at a time)
// - IFFT-based evaluation (naive way of evaluating video's polynomial at a given point. Note that these don't obviously lead to a redactable signature scheme.)
// - Barycentric Evaluation of the video at a random point (Clever way of evaluating video's polynomial at a given point)

// In progress:
// - Poseidon-based Merkle Tree (base case for SNARK-friendly signatures)

use blstrs::Scalar as Fr;
use bytemuck::cast_slice;
use mpcs::util::plonky2_util::log2_ceil;
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::ArcMultilinearExtension,
};
use neptune::poseidon::{HashMode, Poseidon, PoseidonConstants};
// use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
// use p3_symmetric::{
//     CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
// };
use pasta_curves::group::ff::FromUniformBytes;
use pasta_curves::Fp;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::Rng;
use std::time::Instant;
use typenum::U8;
use video_trimming::*;

static FRAME_SIZE: usize = 512 * 512;
static FRAME_COUNT: usize = 3;
static PIXELS: usize = FRAME_SIZE * FRAME_COUNT;

// pub fn hash_with_poseidon(data: Vec<u8>) {
//     type Perm = Poseidon2BabyBear<16>;
//     type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

//     let perm = Perm::new_from_rng_128(&mut rng);
//     let hash = MyHash::new(perm.clone());

//     let mut data_as_felts: Vec<BabyBear> = data
//         .chunks_exact(3)
//         .map(|chunk| {
//             BabyBear::from((chunk[0] as u32) | ((chunk[1] as u32) << 8) | ((chunk[2] as u32) << 16))
//         })
//         .collect();

//     hash.hash_iter(data_as_felts)
// }

fn main() {
    let mut rng = rand::rng();

    let image: Vec<u8> = (0..PIXELS).map(|_| rng.random()).collect();
    let image_copy = image.clone();

    let eval_point = random_felt(rng.random());

    // // IFFT Evaluation Approach
    // let start = Instant::now();
    // let result = ifft_evaluation(image, eval_point);
    // let duration = start.elapsed();
    // println!("IFFT took: {:?}", duration);
    // println!("Result from IFFT: {:?}", result);

    // Merkle Tree approach (dumb)
    // let start = Instant::now();
    // let result1 = image_merkle_tree(image, 32);
    // let duration = start.elapsed();
    // println!("Merklization took: {:?}", duration);
    // println!("Result from IFFT: {:?}", result1.root());

    // Merkle Tree approach (smart)
    // let start = Instant::now();
    // let result1 = image_merkle_tree(image, FRAME_SIZE);
    // let duration = start.elapsed();
    // println!("Merklization took: {:?}", duration);
    // println!("Result from IFFT: {:?}", result1.root());

    // Poseidon hashing approach (not ready, annoying)
    // let start = Instant::now();
    // let result1 = hash_with_poseidon(image);
    // let duration = start.elapsed();
    // println!("Poseidon hash took: {:?}", duration);
    // println!("Result from poseigon: {:?}", result1);

    // Barycentric Approach (with batching)
    // let start = Instant::now();
    // let result = barycentric_evaluation(image_copy, eval_point);
    // let duration = start.elapsed();
    // println!("Barycentric took: {:?}", duration);
    // println!("Result from Barycentric: {:?}", result);

    // let image_u64_copy = image.iter().map(|x| *x as u64).collect::<Vec<_>>();
    // let start = Instant::now();
    // let evaluations_vec =
    //     compute_video_mle_evaluations_vec(&image_u64_copy, FRAME_SIZE, FRAME_COUNT);
    // let num_vars = log2_ceil(evaluations_vec.len());
    // let mle_point = (0..num_vars)
    //     .map(|_| random_felt_ceno(rng.random()))
    //     .collect::<Vec<_>>();
    // let poly = DenseMultilinearExtension::from_evaluations_ext_vec(num_vars, evaluations_vec);
    // let eval = poly.evaluate(&mle_point);
    // let duration = start.elapsed();
    // println!("MLE Eval took: {:?}", duration);
    // println!("Result from MLE Eval: {:?}", eval);

    let start = Instant::now();
    let result = horners_evaluation(image, eval_point);
    let duration = start.elapsed();
    println!("Horners took: {:?}", duration);
    println!("Result from Horners: {:?}", result);
}
