use ff_ext::GoldilocksExt2;
use mpcs::{
    test_util::{
        commit_polys_individually, gen_rand_poly_base, gen_rand_poly_ext, gen_rand_polys,
        get_point_from_challenge, get_points_from_challenge, setup_pcs,
    },
    util::plonky2_util::log2_ceil,
    Basefold, BasefoldBasecodeParams, BasefoldRSParams, Evaluation, PolynomialCommitmentScheme,
};
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::ArcMultilinearExtension,
};
use p3_field_git::PrimeCharacteristicRing;
use rand::Rng;
use std::time::Duration;
use std::time::Instant;
use transcript::{BasicTranscript, Transcript};
use video_trimming::compute_video_mle_evaluations_vec;

type PcsGoldilocksRSCode = Basefold<GoldilocksExt2, BasefoldRSParams>;
type PcsGoldilocksBasecode = Basefold<GoldilocksExt2, BasefoldBasecodeParams>;
type T = BasicTranscript<GoldilocksExt2>;
type E = GoldilocksExt2;
type Pcs = PcsGoldilocksRSCode;

fn main() {
    let frame_size: usize = 240 * 360;
    let m = log2_ceil(frame_size);
    let num_frames: usize = 50;
    let n = log2_ceil(num_frames);
    let num_vars = m + n;
    let poly_size = 1 << num_vars;
    let video_size = num_frames * frame_size;

    let (pp, vp) = {
        let param = Pcs::setup(poly_size).unwrap();
        Pcs::trim(param, poly_size).unwrap()
    };

    // let mut rng = OsRng;
    // let pixels: Vec<u64> = (0..video_size)
    //     .map(|_| rng.try_next_u64().unwrap())
    //     .collect();
    let mut rng = rand::rng();
    let pixels: Vec<u64> = (0..video_size).map(|_| rng.random()).collect();

    // Generate video polynomial:
    let mut evaluations = compute_video_mle_evaluations_vec(&pixels, frame_size, num_frames);

    let commit_start = Instant::now();
    let mut transcript = T::new(b"BaseFold");
    let poly = DenseMultilinearExtension::from_evaluations_ext_vec(num_vars, evaluations);
    let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
    let commit_duration = commit_start.elapsed();
    println!("Gen commitment took: {:?}", commit_duration);

    let opening_proof_start = Instant::now();
    let mut point = get_point_from_challenge(num_vars, &mut transcript);
    for i in 0..n {
        point[num_vars - 1 - i] = E::from_u64(0);
    }
    let eval = poly.evaluate(point.as_slice());
    transcript.append_field_element_ext(&eval);
    // let transcript_for_bench = transcript.clone();
    let proof = Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();
    let opening_proof_duration = opening_proof_start.elapsed();
    println!("Gen opening proof took: {:?}", opening_proof_duration);

    let frame_num = 0;
    let mut frame_contents = Vec::with_capacity(frame_size.next_power_of_two());
    for i in 0..frame_size {
        frame_contents.push(E::from_u64(pixels[frame_num * frame_size + i]));
    }
    for i in frame_size..frame_size.next_power_of_two() {
        frame_contents.push(E::from_u64(0));
    }

    // Verify
    let verify_opening_start = Instant::now();
    let comm = Pcs::get_pure_commitment(&comm);
    let mut transcript = T::new(b"BaseFold");
    Pcs::write_commitment(&comm, &mut transcript).unwrap();
    let mut point = get_point_from_challenge(num_vars, &mut transcript);
    for i in 0..n {
        point[num_vars - 1 - i] = E::from_u64(0);
    }
    transcript.append_field_element_ext(&eval);
    let transcript_for_bench = transcript.clone();
    Pcs::verify(&vp, &comm, &point, &eval, &proof, &mut transcript).unwrap();
    let verify_opening_duration = verify_opening_start.elapsed();
    println!(
        "Verification of opening took: {:?}",
        verify_opening_duration
    );

    let interpolate_polynomial_start = Instant::now();
    let frame_poly = DenseMultilinearExtension::from_evaluations_ext_vec(m, frame_contents);
    let eval2 = frame_poly.evaluate(&point.as_slice()[0..m]);
    let interpolate_polynomial_duration = interpolate_polynomial_start.elapsed();
    println!(
        "Interpolation of polynomial took: {:?}",
        interpolate_polynomial_duration
    );

    println!("Eval of polynomial the regular way is: {:?}", eval);
    println!("Eval of polynomial via interpolation is: {:?}", eval2);
}
