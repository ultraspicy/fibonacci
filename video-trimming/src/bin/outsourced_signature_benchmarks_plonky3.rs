// Plonky3 does not play well with plonky2/arkworks when I import it in the same file.
// It yells at me about using the wrong RNG and other stuff. I didn't benchmark Merkle Tree construction
// since that runtime is insignificant when the leaves are big.
// These are the benchmarks for poseidon merkle trees and poseidon hashing in plonky3.
// I chose plonky3 since this has the best implementations of these functions that I could find.

use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, TruncatedPermutation};

use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::Duration;
use std::time::Instant;

type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Val = BabyBear;

fn seeded_rng() -> impl Rng {
    ChaCha20Rng::seed_from_u64(18)
}

fn main() {
    // Setup the PCS with basic parameters
    let mut rng = seeded_rng();
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixBabyBear::default(),
        &mut rng,
    );
    let hash = MyHash::new(perm.clone());

    static FRAME_SIZE: usize = 1920 * 1080;
    static FRAME_COUNT: usize = 240;
    static PIXELS: usize = FRAME_SIZE * FRAME_COUNT;

    let image: Vec<u8> = (0..PIXELS).map(|_| rng.next_u32() as u8).collect();
    let image_copy = image.clone();

    let start = Instant::now();
    let mut data_as_felts: Vec<BabyBear> = image
        .into_iter()
        .map(|chunk| BabyBear::new((chunk as u32)))
        .collect();

    hash.hash_iter(data_as_felts);
    let duration = start.elapsed();
    println!("Poseidon Hashing took: {:?}", duration);
}
