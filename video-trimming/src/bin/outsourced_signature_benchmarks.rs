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
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, TruncatedPermutation};

use std::time::Instant;
use video_trimming::*;

use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Val = BabyBear;

static FRAME_SIZE: usize = 1920 * 1080;
static FRAME_COUNT: usize = 240;
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

fn seeded_rng() -> impl Rng {
    ChaCha20Rng::seed_from_u64(18)
}

fn main() {
    let mut rng = seeded_rng();

    let image: Vec<u8> = (0..PIXELS).map(|_| rng.next_u32() as u8).collect();

    let eval_point = random_felt(rng.next_u64(), rng.next_u64());

    // // IFFT Evaluation Approach
    // let start = Instant::now();
    // let result = ifft_evaluation(image, eval_point);
    // let duration = start.elapsed();
    // println!("IFFT took: {:?}", duration);
    // println!("Result from IFFT: {:?}", result);

    // Merkle Tree approach (dumb)
    // let start = Instant::now();
    // let result1 = image_merkle_tree(image.clone(), 32);
    // let duration = start.elapsed();
    // println!("Merklization took: {:?}", duration);
    // println!("Result from Merklization: {:?}", result1.root());

    // Merkle Tree approach (smart)
    // let start = Instant::now();
    // let result1 = image_merkle_tree(image.clone(), FRAME_SIZE);
    // let duration = start.elapsed();
    // println!("Merklization took: {:?}", duration);
    // println!("Result from Merklization: {:?}", result1.root());

    // Poseidon Approach (basically same perf as poseidon merkle tree)
    // let perm = Perm::new_from_rng_128(
    //     Poseidon2ExternalMatrixGeneral,
    //     DiffusionMatrixBabyBear::default(),
    //     &mut rng,
    // );
    // let hash = MyHash::new(perm.clone());
    // let mut data_as_felts: Vec<BabyBear> = image
    //     .clone()
    //     .into_iter()
    //     .map(|chunk| BabyBear::new((chunk as u32)))
    //     .collect();
    // let start = Instant::now();
    // hash.hash_iter(data_as_felts);
    // let duration = start.elapsed();
    // println!("Poseidon Hashing took: {:?}", duration);

    // Barycentric Approach (with batching)
    let start = Instant::now();
    let result = barycentric_evaluation(image.clone(), eval_point);
    let duration = start.elapsed();
    println!("Barycentric took: {:?}", duration);
    println!("Result from Barycentric: {:?}", result);

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
