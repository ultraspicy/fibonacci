use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead};
use std::marker::PhantomData;
use std::path::Path;

use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, RngCore, SeedableRng};
use either::Either;
use itertools::{izip, Itertools};
use rand::{rngs::OsRng, TryRngCore};

use std::time::Duration;
use std::time::Instant;

use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_commit::Mmcs;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Dimensions;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

use p3_merkle_tree::FieldMerkleTreeMmcs;

type F = BabyBear;

type Perm = Poseidon2<F, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type MyMmcs =
    FieldMerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;

fn parse_filename(file_name: &str) -> Option<(u32, char)> {
    let parts: Vec<&str> = file_name.trim_end_matches(".txt").split('_').collect();
    if parts.len() == 3 {
        if let Ok(frame_number) = parts[1].parse::<u32>() {
            if let Some(channel) = parts[2].chars().next() {
                return Some((frame_number, channel));
            }
        }
    }
    None
}

fn read_file_as_vec<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut values = Vec::new();

    for line in reader.lines() {
        let line = line?;
        values.extend(
            line.split_whitespace()
                .filter_map(|num| num.parse::<u8>().ok()),
        );
    }

    Ok(values)
}

fn seeded_rng() -> impl Rng {
    StdRng::seed_from_u64(18)
}

fn main() -> io::Result<()> {
    let file_io_start = Instant::now();
    // Define image vector/properties.
    let frame_size: usize = (720 * 1280);
    let num_frames = 25 * 10; // 10 frames at 25 fps
    let video_size = num_frames * frame_size;

    // Read full video for the signature part.
    let dir_path = "../demo/decomposed_frames";
    let mut signer_frames: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();

    let entries = fs::read_dir(dir_path)?;

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name().into_string().unwrap();

        if let Some((frame_number, channel)) = parse_filename(&file_name) {
            if (frame_number as usize) <= num_frames {
                let file_path = entry.path();
                let content = read_file_as_vec(&file_path)?;

                let frame = signer_frames
                    .entry(frame_number)
                    .or_insert_with(|| vec![vec![], vec![], vec![]]);
                match channel {
                    'B' => frame[0] = content,
                    'G' => frame[1] = content,
                    'R' => frame[2] = content,
                    _ => (),
                }
            }
        }
    }

    // Note: BTreeMap is already sorted by frame count.
    let sorted_frames = signer_frames
        .into_values()
        .flatten()
        .flatten()
        .collect::<Vec<_>>();
    let mut video_packed_into_felts = sorted_frames
        .chunks_exact(3)
        .map(|chunk| (chunk[0] as u32) | ((chunk[1] as u32) << 8) | ((chunk[2] as u32) << 16))
        .map(|x| BabyBear::new(x))
        .collect::<Vec<BabyBear>>();
    let file_io_duration = file_io_start.elapsed();
    println!(
        "Signer reading and setting up video took: {:?}",
        file_io_duration
    );

    let commit_start = Instant::now();
    let mut rng = seeded_rng();
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixBabyBear::default(),
        &mut rng,
    );
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm);
    let mmcs = MyMmcs::new(hash, compress);

    static INDEX_FOR_MEMBERSHIP_PROOF_SHORT: usize = 1;
    let INDICES_FOR_MEMBERSHIP_PROOF_LONG: Vec<usize> = (1..240).collect::<Vec<_>>();

    let video_matrix = RowMajorMatrix::new(video_packed_into_felts, frame_size);

    let (commit, prover_data) = mmcs.commit(vec![video_matrix]);
    let commit_duration = commit_start.elapsed();
    println!("Computing commitments took: {:?}", commit_duration);

    let opening_proof_1_start = Instant::now();
    let proof_short = mmcs.open_batch(INDEX_FOR_MEMBERSHIP_PROOF_SHORT, &prover_data);

    let opening_proof_1_duration = opening_proof_1_start.elapsed();
    println!("Gen opening proof 1 took: {:?}", opening_proof_1_duration);

    let opening_proof_2_start = Instant::now();
    let mut long_proofs = Vec::new();
    for index in &INDICES_FOR_MEMBERSHIP_PROOF_LONG {
        let proof = mmcs.open_batch(*index, &prover_data);
        long_proofs.push(proof);
    }

    let opening_proof_2_duration = opening_proof_2_start.elapsed();
    println!("Gen opening proofs 2 took: {:?}", opening_proof_2_duration);

    // Verify
    let verify_1_start = Instant::now();
    let video_matrix_dims = vec![Dimensions {
        height: num_frames,
        width: frame_size,
    }];
    let (opened_values, proof) = proof_short;
    mmcs.verify_batch(
        &commit,
        &video_matrix_dims,
        INDEX_FOR_MEMBERSHIP_PROOF_SHORT,
        &opened_values,
        &proof,
    )
    .expect("expected verification to succeed");

    let verify_1_duration = verify_1_start.elapsed();
    println!("Verification of opening 1 took: {:?}", verify_1_duration);

    let verify_2_start = Instant::now();
    for (idx, proof_tuple) in long_proofs.iter().enumerate() {
        let (opened_values, proof) = proof_tuple;
        mmcs.verify_batch(
            &commit,
            &video_matrix_dims,
            INDICES_FOR_MEMBERSHIP_PROOF_LONG[idx],
            &opened_values,
            &proof,
        )
        .expect("expected verification to succeed");
    }

    let verify_2_duration = verify_2_start.elapsed();
    println!("Verification of opening 2 took: {:?}", verify_2_duration);
    Ok(())
}
