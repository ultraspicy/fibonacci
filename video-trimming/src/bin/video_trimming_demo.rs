use clap::Parser;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead};
use std::marker::PhantomData;
use std::path::Path;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_keccak::Keccak256Hash;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};

use ark_std::log2;
use itertools::{izip, Itertools};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};

use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, RngCore, SeedableRng};
use p3_challenger::{CanObserve, DuplexChallenger, FieldChallenger};
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeField64;
use p3_field::{AbstractField, ExtensionField, Field};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, TryRngCore};
use std::time::Instant;

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;

type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 8, 7>;
type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;
type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;

type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

type Dft = Radix2DitParallel;
type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

#[derive(Parser, Debug)]
#[command(name = "video_pcs")]
#[command(about = "PCS-based video proof tool", long_about = None)]
struct Opt {
    /// Use a long segment (frames 3..240 instead of 3..3)
    #[arg(long)]
    use_long_segment: bool,
}

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
    let opt = Opt::parse();
    let file_io_start = Instant::now();

    // Each Goldilocks element encodes 6 bytes; each pixel is 3 bytes (RGB).
    // For a 720x1280 frame, that gives (720 * 1280 * 3) / 6 = (720 * 1280) / 2 coefficients.
    let frame_size: usize = (720 * 1280) / 2; // coeffs per frame

    // Python-style [start, end) indices over 0-based frame indices.
    // ffmpeg frames are 1-based.
    let segment_start: usize = 2 - 1;
    let segment_end: usize = if opt.use_long_segment { 240 - 1 } else { 3 - 1 };
    let segment_frames: usize = segment_end - segment_start;

    let num_frames = 25 * 10; // Total number of frames in the *full* video.
    let video_size = num_frames * frame_size;
    let log_n = log2(video_size); // ark_std::log2 is ceil-log2; 1 << log_n is a power of two ≥ video_size.

    // Read full video for the signer side.
    let dir_path = "../demo/decomposed_frames";
    let mut signer_frames: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();

    let entries = fs::read_dir(dir_path)?;

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name().into_string().unwrap();

        if let Some((frame_number, channel)) = parse_filename(&file_name) {
            if (frame_number as usize) <= num_frames && (frame_number as usize) > 0 {
                // ffmpeg 1-indexes frames
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

    // BTreeMap is sorted by frame number.
    let sorted_frames = signer_frames
        .into_values()
        .flatten()
        .flatten()
        .collect::<Vec<_>>();

    let mut signer_u64s: Vec<u64> = sorted_frames
        .chunks_exact(6)
        .map(|chunk| {
            (chunk[0] as u64)
                | ((chunk[1] as u64) << 8)
                | ((chunk[2] as u64) << 16)
                | ((chunk[3] as u64) << 24)
                | ((chunk[4] as u64) << 32)
                | ((chunk[5] as u64) << 40)
        })
        .collect();

    // // Sanity check: full video matches num_frames * frame_size before padding.
    // let expected_full_coeffs = num_frames * frame_size;
    // assert_eq!(
    //     signer_u64s.len(),
    //     expected_full_coeffs,
    //     "Full video has {} coefficients, expected {} ({} frames * {} coeffs/frame)",
    //     signer_u64s.len(),
    //     expected_full_coeffs,
    //     num_frames,
    //     frame_size,
    // );

    // Pad the *full* polynomial up to the power-of-two size required by FRI.
    while signer_u64s.len() < (1 << log_n) {
        signer_u64s.push(0);
    }

    let signer_pixel_felts = signer_u64s
        .into_iter()
        .map(|x| Goldilocks::from_canonical_u64(x))
        .collect::<Vec<_>>();
    let signer_pixel_felts_clone = signer_pixel_felts.clone();

    let file_io_duration = file_io_start.elapsed();
    println!(
        "Signer reading and setting up video took: {:?}",
        file_io_duration
    );

    let setup_and_commit_start = Instant::now();
    // Setup the PCS with basic parameters
    let mut rng = seeded_rng();
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks::default(),
        &mut rng,
    );
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());

    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    // Use log blowup 1 for now.
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let pcs = MyPcs::new(Dft {}, val_mmcs, fri_config);
    let challenger = Challenger::new(perm.clone());

    let mut p_challenger = challenger.clone();

    // Setup for commitment to polynomial of image
    let d = <MyPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
        &pcs,
        1 << log_n,
    );

    // Coefficients are just the packed pixel field elements (Horner's rule).
    let coeffs = RowMajorMatrix::new(signer_pixel_felts, 1);
    let dft = Dft::default();

    let evals = dft.dft_batch(coeffs).to_row_major_matrix();

    let just_commit_start = Instant::now();
    let (comm, data) =
        <MyPcs as p3_commit::Pcs<Challenge, Challenger>>::commit(&pcs, vec![(d, evals)]);
    let just_commit_duration = just_commit_start.elapsed();
    let commit_duration = setup_and_commit_start.elapsed();

    // Now sign the commitment
    let mut comm_bytes = Vec::with_capacity(32); // 1 Poseidon hash ≈ 32 bytes.
    for felt in comm {
        comm_bytes.extend((felt.as_canonical_u64()).to_le_bytes());
    }

    // Generate a new keypair
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).unwrap();

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = VerifyingKey::from(&signing_key);

    // Sign the message using the keypair
    let signature: Signature = signing_key.sign(&comm_bytes);

    // println!("Value of comm is: {:?}", comm);
    println!(
        "Generating relevant sized PCS took: {:?}",
        just_commit_duration
    );
    println!("Setup/Gen commitment took: {:?}", commit_duration);

    let opening_proof_start = Instant::now();

    // ==== Build R and Q polynomials corresponding to prefix/suffix ====

    let r_size = frame_size * segment_start;
    let r_degree = r_size.next_power_of_two();
    let mut r_coeffs_vec = Vec::new();
    for _ in 0..(r_degree - r_size) {
        r_coeffs_vec.push(Goldilocks::from_canonical_u64(0));
    }
    for e in &signer_pixel_felts_clone[0..frame_size * segment_start] {
        r_coeffs_vec.push(*e);
    }
    let r_coeffs = RowMajorMatrix::new(r_coeffs_vec, 1);
    let r_evals = dft.dft_batch(r_coeffs).to_row_major_matrix();
    let r_domain =
        <MyPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, r_degree);

    let q_size = signer_pixel_felts_clone.len() - frame_size * segment_end;
    let q_degree = q_size.next_power_of_two();
    let mut q_coeffs_vec = Vec::new();
    for _ in 0..(q_degree - q_size) {
        q_coeffs_vec.push(Goldilocks::from_canonical_u64(0));
    }
    for e in &signer_pixel_felts_clone[frame_size * segment_end..signer_pixel_felts_clone.len()] {
        q_coeffs_vec.push(*e);
    }
    let q_coeffs = RowMajorMatrix::new(q_coeffs_vec, 1);
    let q_evals = dft.dft_batch(q_coeffs).to_row_major_matrix();
    let q_domain =
        <MyPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, q_degree);

    let (trim_comm, trim_data) = <MyPcs as p3_commit::Pcs<Challenge, Challenger>>::commit(
        &pcs,
        vec![(r_domain, r_evals), (q_domain, q_evals)],
    );

    // TODO: Make zeta be based on trim_comm, trim_data and overall comm
    let zeta: Challenge = rng.gen();

    let (values, proof) = pcs.open(
        vec![
            (&data, vec![vec![zeta]]),
            (&trim_data, vec![vec![zeta], vec![zeta]]),
        ],
        &mut p_challenger,
    );
    let opening_proof_duration = opening_proof_start.elapsed();
    println!(
        "Generating trimming proof took: {:?}",
        opening_proof_duration
    );

    // ==== Verification side: read trimmed video and build segment polynomial F ====

    let verification_read_start = Instant::now();
    let dir_path = "../demo/decomposed_frames";
    let mut verifier_frames: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();

    let entries = fs::read_dir(dir_path)?;

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name().into_string().unwrap();

        if let Some((frame_number, channel)) = parse_filename(&file_name) {
            if (frame_number as usize) < (segment_end + 1)
                && (frame_number as usize) >= (segment_start + 1)
            {
                let file_path = entry.path();
                let content = read_file_as_vec(&file_path)?;

                let frame = verifier_frames
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

    let verififer_sorted_frames = verifier_frames
        .into_values()
        .flatten()
        .flatten()
        .collect::<Vec<_>>();

    let verifier_u64s: Vec<u64> = verififer_sorted_frames
        .chunks_exact(6)
        .map(|chunk| {
            (chunk[0] as u64)
                | ((chunk[1] as u64) << 8)
                | ((chunk[2] as u64) << 16)
                | ((chunk[3] as u64) << 24)
                | ((chunk[4] as u64) << 32)
                | ((chunk[5] as u64) << 40)
        })
        .collect();

    // // Sanity check: trimmed video length matches the segment length.
    // assert_eq!(
    //     verifier_u64s.len(),
    //     frame_size * segment_frames,
    //     "Trimmed video has {} coefficients, expected {} \
    //      ({} frames * {} coeffs/frame)",
    //     verifier_u64s.len(),
    //     frame_size * segment_frames,
    //     segment_frames,
    //     frame_size,
    // );

    let verifier_pixel_felts = verifier_u64s
        .into_iter()
        .map(|x| Goldilocks::from_canonical_u64(x))
        .collect::<Vec<_>>();

    let verification_read_duration = verification_read_start.elapsed();
    println!(
        "Verification file read took: {:?}",
        verification_read_duration
    );

    // ==== Verify PCS proof and reconstruct P(zeta) from R, F, Q ====

    let verification_start = Instant::now();

    // Verify signature.
    verifying_key
        .verify(&comm_bytes, &signature)
        .expect("Signature verification should succeed");

    let mut v_challenger = challenger.clone();
    let _result = pcs
        .verify(
            vec![
                (comm, vec![(d, vec![(zeta, values[0][0][0].clone())])]),
                (
                    trim_comm,
                    vec![
                        (r_domain, vec![(zeta, values[1][0][0].clone())]),
                        (q_domain, vec![(zeta, values[1][1][0].clone())]),
                    ],
                ),
            ],
            &proof,
            &mut v_challenger,
        )
        .unwrap();

    // Evaluate the segment polynomial F at zeta using the trimmed data.
    let segment_eval_start = Instant::now();
    let mut segment_eval = Challenge::zero();
    for i in verifier_pixel_felts.iter().rev() {
        segment_eval *= zeta;
        segment_eval += *i;
    }
    let segment_eval_duration = segment_eval_start.elapsed();
    println!("segment eval took: {:?}", segment_eval_duration);

    // Remove padding exponents from R(zeta) and Q(zeta).
    let r_padding_degree = r_degree - r_size;
    let r_extra_pow = zeta.exp_u64(r_padding_degree as u64);
    let r_proof_value = values[1][0][0][0].clone();
    let r_actual = r_proof_value / r_extra_pow;

    let q_padding_degree = q_degree - q_size;
    let q_extra_pow = zeta.exp_u64(q_padding_degree as u64);
    let q_proof_value = values[1][1][0][0].clone();
    let q_actual = q_proof_value / q_extra_pow;

    // Shift Q and F into their correct positions inside P.
    let q_shift_factor = zeta.exp_u64((frame_size * segment_end) as u64);
    let f_shift_factor = zeta.exp_u64((frame_size * segment_start) as u64);

    let eval_value_from_pcs = values[0][0][0][0];

    let inferred_eval_value = q_actual * q_shift_factor + segment_eval * f_shift_factor + r_actual;

    let verification_duration = verification_start.elapsed();
    println!("Verification took: {:?}", verification_duration);
    println!("Overall eval value is: {:?}", eval_value_from_pcs);
    println!("Inferred eval value is: {:?}", inferred_eval_value);

    if eval_value_from_pcs == inferred_eval_value {
        Ok(())
    } else {
        panic!("Signature scheme not behaving correctly");
    }
}
