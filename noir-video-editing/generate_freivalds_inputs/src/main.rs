use ark_bn254::Fr;
use ark_ff::Field;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use std::process;
use toml;

static SIGMA: f64 = 10.0;
static GBLUR_RADIUS: usize = 30;
static KERNEL_SCALE: u64 = 1u64 << 32;
static FILTER_BITS: usize = 16;

const DELTA_BATCH_SIZE: usize = 10;
const MAX_DELTA_LENGTH: usize = 128 * 360; // max 460,800 changed pixels (~50% of frame)

// ── Prover.toml structs ──────────────────────────────────────────────────────

/// Keyframe circuit inputs (video_blurring).
#[derive(Debug, Deserialize, Serialize)]
struct ProverInputs {
    original_image: Vec<Vec<String>>,
    target_middle_image: Vec<Vec<String>>,
    edited_image: Vec<Vec<String>>,
    r: Vec<String>,
    s: Vec<String>,
    rTA: Vec<String>,
    As: Vec<String>,
    #[serde(flatten)]
    other: toml::Value,
}

/// Read just original_image from any Prover.toml (used to load the previous frame).
#[derive(Debug, Deserialize)]
struct ProverInputsMinimal {
    original_image: Vec<Vec<String>>,
}

/// Non-keyframe circuit inputs (non_keyframe_edits).
#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct DeltaProverInputs {
    delta_batches: Vec<Vec<String>>,
    delta_is: Vec<String>,
    delta_js: Vec<Vec<String>>,
    /// r^T × (blur(current) - blur(prev)) × s, computed outside the circuit.
    /// The circuit verifies this equals r^T × A × (current - prev) × s (sparse).
    rT_delta_blur_s: String,
    r: Vec<String>,
    s: Vec<String>,
    rTA: Vec<String>,
    As: Vec<String>,
}

// ── Matrix type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum MatrixType {
    Tridiagonal,
    Resizing,
    GBlur,
}

// ── Field helpers ────────────────────────────────────────────────────────────

fn gen_rand_scalar() -> Fr {
    let mut rng = rand::thread_rng();
    loop {
        let random_bytes: [u8; 32] = rng.gen();
        if let Some(val) = Fr::from_random_bytes(&random_bytes) {
            return val;
        }
    }
}

fn gen_scalar(val: u64) -> Fr {
    Fr::from(val)
}

fn scalar_vec_to_string_vec(v: Vec<Fr>) -> Vec<String> {
    v.into_iter().map(|x| format!("{:?}", x.clone())).collect()
}

fn scalar_matrix_to_string_matrix(arr: Vec<Vec<Fr>>) -> Vec<Vec<String>> {
    arr.into_iter()
        .map(|v| v.into_iter().map(|x| format!("{:?}", x.clone())).collect())
        .collect()
}

// ── Linear algebra ───────────────────────────────────────────────────────────

fn inner_product(u: &[Fr], v: &[Fr]) -> Fr {
    assert_eq!(u.len(), v.len());
    u.iter().zip(v.iter()).fold(Fr::zero(), |acc, (a, b)| acc + *a * *b)
}

fn matrix_vector_product(a: &[Vec<Fr>], v: &[Fr]) -> Vec<Fr> {
    a.iter().map(|row| {
        row.iter().zip(v.iter()).fold(Fr::zero(), |acc, (a, b)| acc + *a * *b)
    }).collect()
}

fn vector_matrix_product(v: &[Fr], a: &[Vec<Fr>]) -> Vec<Fr> {
    let width = a[0].len();
    let mut output = vec![Fr::zero(); width];
    for (i, row) in a.iter().enumerate() {
        for (j, &val) in row.iter().enumerate() {
            output[j] += val * v[i];
        }
    }
    output
}

fn matrix_matrix_product(a: &[Vec<Fr>], b: &[Vec<Fr>]) -> Vec<Vec<Fr>> {
    let b_width = b[0].len();
    a.par_iter().map(|a_row| {
        let mut row = vec![Fr::zero(); b_width];
        for j in 0..b_width {
            for k in 0..a_row.len() {
                row[j] += a_row[k] * b[k][j];
            }
        }
        row
    }).collect()
}

fn matrix_matrix_product_band_left(a: &[Vec<Fr>], b: &[Vec<Fr>], kernel_width: usize) -> Vec<Vec<Fr>> {
    let a_width = a[0].len();
    let b_width = b[0].len();
    a.par_iter().enumerate().map(|(i, a_row)| {
        let mut row = vec![Fr::zero(); b_width];
        let k_start = i.saturating_sub(kernel_width);
        let k_end = (i + kernel_width + 1).min(a_width);
        for j in 0..b_width {
            for k in k_start..k_end {
                row[j] += a_row[k] * b[k][j];
            }
        }
        row
    }).collect()
}

fn matrix_matrix_product_band_right(a: &[Vec<Fr>], b: &[Vec<Fr>], kernel_width: usize) -> Vec<Vec<Fr>> {
    let b_height = b.len();
    let b_width = b[0].len();
    a.par_iter().map(|a_row| {
        let mut row = vec![Fr::zero(); b_width];
        for j in 0..b_width {
            let k_start = j.saturating_sub(kernel_width);
            let k_end = (j + kernel_width + 1).min(b_height);
            for k in k_start..k_end {
                row[j] += a_row[k] * b[k][j];
            }
        }
        row
    }).collect()
}

// ── Matrix constructors ──────────────────────────────────────────────────────

fn create_tridiagonal_matrix(size: usize) -> Vec<Vec<Fr>> {
    let mut matrix = vec![vec![Fr::zero(); size]; size];
    for i in 0..size {
        matrix[i][i] = Fr::one();
        if i + 1 < size { matrix[i][i + 1] = Fr::one(); }
        if i > 0 { matrix[i][i - 1] = Fr::one(); }
    }
    matrix
}

fn create_resizing_matrix(src_size: usize, dst_size: usize, for_horizontal: bool) -> Vec<Vec<Fr>> {
    let matrix = create_resize_matrix_impl(src_size, dst_size);
    if for_horizontal { transpose(matrix) } else { matrix }
}

fn create_resize_matrix_impl(src_size: usize, dst_size: usize) -> Vec<Vec<Fr>> {
    let filter_size = 4;
    let mut matrix = vec![vec![Fr::zero(); src_size]; dst_size];
    let x_inc = ((src_size << 16) / dst_size + 1) >> 1;
    for i in 0..dst_size {
        let src_pos = (i * x_inc) >> 15;
        let xx_inc = x_inc & 0xffff;
        let xx = (xx_inc * (1 << FILTER_BITS)) / x_inc;
        for j in 0..filter_size {
            let coeff_u64 = if j == 0 { (1u64 << FILTER_BITS) - (xx as u64) } else { xx as u64 };
            let src_idx = src_pos + j;
            if src_idx < src_size { matrix[i][src_idx] = Fr::from(coeff_u64); }
        }
    }
    matrix
}

fn diff_within_threshold(target: Fr, edited: Fr, threshold: u64) -> bool {
    let diff = target - edited;
    if diff.is_zero() { return true; }
    let repr = diff.into_bigint();
    if repr.0[1] == 0 && repr.0[2] == 0 && repr.0[3] == 0 && repr.0[0] <= threshold {
        return true;
    }
    let neg_repr = (-diff).into_bigint();
    neg_repr.0[1] == 0 && neg_repr.0[2] == 0 && neg_repr.0[3] == 0 && neg_repr.0[0] <= threshold
}

fn snap_to_target(target: &[Vec<Fr>], edited: &mut Vec<Vec<Fr>>, threshold: u64) {
    let mut snapped = 0usize;
    let total = target.len() * target[0].len();
    for i in 0..target.len() {
        for j in 0..target[i].len() {
            if diff_within_threshold(target[i][j], edited[i][j], threshold) {
                edited[i][j] = target[i][j];
                snapped += 1;
            }
        }
    }
    println!("Snapped {}/{} pixels to zero diff ({:.1}% sparse)", snapped, total, 100.0 * snapped as f64 / total as f64);
}

fn transpose(matrix: Vec<Vec<Fr>>) -> Vec<Vec<Fr>> {
    let rows = matrix.len();
    if rows == 0 { return vec![]; }
    let cols = matrix[0].len();
    let mut transposed = vec![vec![Fr::zero(); rows]; cols];
    for i in 0..rows {
        for j in 0..cols {
            transposed[j][i] = matrix[i][j].clone();
        }
    }
    transposed
}

fn gaussian_kernel1d(sigma: f64, radius: i32) -> Vec<f64> {
    let sigma2 = sigma * sigma;
    let mut phi_x: Vec<f64> = (-radius..=radius).map(|i| (-0.5 / sigma2 * (i as f64).powi(2)).exp()).collect();
    let sum: f64 = phi_x.iter().sum();
    phi_x.iter_mut().for_each(|val| *val /= sum);
    phi_x
}

fn gaussian_kernel1d_fixed_point(sigma: f64, radius: i32) -> Vec<Fr> {
    gaussian_kernel1d(sigma, radius).iter().map(|&x| Fr::from((x * KERNEL_SCALE as f64) as u64)).collect()
}

fn create_gblur_matrix(size: usize, sigma: f64, radius: usize) -> Vec<Vec<Fr>> {
    let mut matrix = vec![vec![Fr::zero(); size]; size];
    let kernel = gaussian_kernel1d_fixed_point(sigma, radius as i32);
    let kernel_len = kernel.len();
    for i in 0..size {
        let left_overflow = if i < radius { radius - i } else { 0 };
        let right_overflow = if i + radius >= size { i + radius - size + 1 } else { 0 };
        let left_mass: Fr = (0..left_overflow).map(|j| kernel[j]).fold(Fr::zero(), |acc, x| acc + x);
        let right_mass: Fr = (kernel_len - right_overflow..kernel_len).map(|j| kernel[j]).fold(Fr::zero(), |acc, x| acc + x);
        for (k_idx, j) in (i.saturating_sub(radius)..=(i + radius).min(size - 1)).enumerate() {
            matrix[i][j] = kernel[left_overflow + k_idx];
        }
        if left_overflow > 0 { matrix[i][0] = matrix[i][0] + left_mass; }
        if right_overflow > 0 { matrix[i][size - 1] = matrix[i][size - 1] + right_mass; }
    }
    matrix
}

fn create_matrix(matrix_type: MatrixType, size: usize, need_transpose: bool) -> Vec<Vec<Fr>> {
    match matrix_type {
        MatrixType::Tridiagonal => create_tridiagonal_matrix(size),
        MatrixType::Resizing => create_resizing_matrix(size, size / 2, need_transpose),
        MatrixType::GBlur => create_gblur_matrix(size, SIGMA, GBLUR_RADIUS),
    }
}

fn parse_matrix_type(s: &str) -> Result<MatrixType, String> {
    match s.to_lowercase().as_str() {
        "tridiagonal" => Ok(MatrixType::Tridiagonal),
        "resizing" => Ok(MatrixType::Resizing),
        "gblur" => Ok(MatrixType::GBlur),
        _ => Err(format!("Invalid matrix type '{}'. Valid options: tridiagonal, resizing, gblur", s)),
    }
}

// ── Delta helpers ────────────────────────────────────────────────────────────

/// Load original_image from a Prover.toml at the given path.
fn load_image(path: &Path) -> Vec<Vec<Fr>> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| { eprintln!("Failed to read {}: {}", path.display(), e); process::exit(1); });
    let inputs: ProverInputsMinimal = toml::from_str(&contents)
        .unwrap_or_else(|e| { eprintln!("Failed to parse {}: {}", path.display(), e); process::exit(1); });
    inputs.original_image.iter()
        .map(|row| row.iter().map(|s| gen_scalar(s.parse::<u64>().expect("bad pixel"))).collect())
        .collect()
}

/// Apply Gaussian blur to an image using precomputed matrices.
fn apply_gblur(image: &[Vec<Fr>], v_matrix: &[Vec<Fr>], h_matrix: &[Vec<Fr>]) -> Vec<Vec<Fr>> {
    let row_wise = matrix_matrix_product_band_left(v_matrix, image, GBLUR_RADIUS);
    matrix_matrix_product_band_right(&row_wise, h_matrix, GBLUR_RADIUS)
}

/// Compute sparse delta batches between two frames.
/// snap_threshold: if Some(t), pixels where |diff| <= t are treated as zero (maximise sparsity).
fn compute_delta_batches(
    frame_a: &[Vec<Fr>],
    frame_b: &[Vec<Fr>],
    snap_threshold: Option<u64>,
) -> (Vec<Vec<Fr>>, Vec<Fr>, Vec<Vec<Fr>>) {
    let height = frame_a.len();
    let mut all_batches: Vec<Vec<Fr>> = Vec::new();
    let mut all_is: Vec<Fr> = Vec::new();
    let mut all_js: Vec<Vec<Fr>> = Vec::new();

    'outer: for i in 0..height {
        let row_changes: Vec<(usize, Fr)> = frame_a[i].iter()
            .zip(frame_b[i].iter())
            .enumerate()
            .filter_map(|(j, (a, b))| {
                if let Some(thresh) = snap_threshold {
                    if diff_within_threshold(*a, *b, thresh) { return None; }
                }
                let d = *a - *b;
                if d.is_zero() { None } else { Some((j, d)) }
            })
            .collect();

        for chunk in row_changes.chunks(DELTA_BATCH_SIZE) {
            let mut vals = vec![Fr::zero(); DELTA_BATCH_SIZE];
            let mut cols = vec![Fr::zero(); DELTA_BATCH_SIZE];
            for (k, &(j, d)) in chunk.iter().enumerate() {
                vals[k] = d;
                cols[k] = Fr::from(j as u64);
            }
            all_batches.push(vals);
            all_is.push(Fr::from(i as u64));
            all_js.push(cols);
            if all_batches.len() >= MAX_DELTA_LENGTH {
                eprintln!("Warning: delta exceeds MAX_DELTA_LENGTH={}, truncating", MAX_DELTA_LENGTH);
                break 'outer;
            }
        }
    }

    // Pad to MAX_DELTA_LENGTH with zero entries (zero pixel_change contributes nothing to sums)
    while all_batches.len() < MAX_DELTA_LENGTH {
        all_batches.push(vec![Fr::zero(); DELTA_BATCH_SIZE]);
        all_is.push(Fr::zero());
        all_js.push(vec![Fr::zero(); DELTA_BATCH_SIZE]);
    }

    (all_batches, all_is, all_js)
}

// ── Modes ────────────────────────────────────────────────────────────────────

/// Keyframe mode: prove full frame blur via dense Freivalds (video_blurring circuit).
fn run_keyframe_mode(args: &[String]) {
    let matrix_type = if args.len() > 1 {
        match parse_matrix_type(&args[1]) {
            Ok(mt) => mt,
            Err(e) => {
                eprintln!("Error: {}", e);
                eprintln!("Usage: {} [gblur|tridiagonal|resizing]", args[0]);
                process::exit(1);
            }
        }
    } else {
        MatrixType::Tridiagonal
    };

    let adjust_factor = match matrix_type { MatrixType::Resizing => 2, _ => 1 };
    println!("Using matrix type: {:?}", matrix_type);

    let config_path = Path::new("Prover.toml");
    if !config_path.exists() {
        eprintln!("Error: Prover.toml does not exist.");
        process::exit(1);
    }

    let contents = fs::read_to_string(config_path).expect("Failed to read Prover.toml");
    let mut prover_inputs: ProverInputs = toml::from_str(&contents).expect("Failed to parse TOML");

    let image_height = prover_inputs.original_image.len();
    let image_width = prover_inputs.original_image[0].len();

    let random_image: Vec<Vec<Fr>> = prover_inputs.original_image.iter()
        .map(|row| row.iter().map(|s| gen_scalar(s.parse::<u64>().expect("bad pixel"))).collect())
        .collect();

    let horizontal_edit_matrix = create_matrix(matrix_type, image_width, true);
    let vertical_edit_matrix = create_matrix(matrix_type, image_height, false);

    println!("Image dimensions: {} × {} (height × width)", image_height, image_width);
    println!("Horizontal matrix dimensions: {} × {}", horizontal_edit_matrix.len(), horizontal_edit_matrix[0].len());
    println!("Vertical matrix dimensions: {} × {}", vertical_edit_matrix.len(), vertical_edit_matrix[0].len());

    let bandwidth = match matrix_type { MatrixType::Resizing => 4, MatrixType::GBlur => GBLUR_RADIUS, MatrixType::Tridiagonal => 1 };

    let row_wise_edited_image = if matches!(matrix_type, MatrixType::Resizing) {
        matrix_matrix_product(&vertical_edit_matrix, &random_image)
    } else {
        matrix_matrix_product_band_left(&vertical_edit_matrix, &random_image, bandwidth)
    };

    let edited_image = if matches!(matrix_type, MatrixType::Resizing) {
        matrix_matrix_product(&row_wise_edited_image, &horizontal_edit_matrix)
    } else {
        matrix_matrix_product_band_right(&row_wise_edited_image, &horizontal_edit_matrix, bandwidth)
    };

    let target_middle_image = edited_image.clone();

    let mut edited_image = if prover_inputs.edited_image.is_empty() {
        edited_image.clone()
    } else {
        prover_inputs.edited_image.iter()
            .map(|row| row.iter().map(|s| gen_scalar(s.parse::<u64>().expect("bad pixel"))).collect())
            .collect()
    };

    let snap_threshold: u64 = 9;
    snap_to_target(&target_middle_image, &mut edited_image, snap_threshold);

    let mut rng = rand::thread_rng();
    let r: Vec<_> = (0..image_height / adjust_factor).map(|_| gen_rand_scalar()).collect();
    println!("r dimensions: {}", r.len());

    let rTA = vector_matrix_product(&r, &vertical_edit_matrix);
    let s: Vec<_> = (0..image_width / adjust_factor).map(|_| gen_rand_scalar()).collect();
    let As = matrix_vector_product(&horizontal_edit_matrix, &s);

    let rTAI = vector_matrix_product(&rTA, &random_image);
    let rTAIAs = inner_product(&rTAI, &As);
    let rTF = vector_matrix_product(&r, &target_middle_image);
    let rTFs = inner_product(&rTF, &s);

    println!("LHS: {:?}", rTAIAs);
    println!("RHS: {:?}", rTFs);

    prover_inputs.original_image = scalar_matrix_to_string_matrix(random_image);
    prover_inputs.target_middle_image = scalar_matrix_to_string_matrix(target_middle_image);
    prover_inputs.edited_image = scalar_matrix_to_string_matrix(edited_image);
    prover_inputs.r = scalar_vec_to_string_vec(r);
    prover_inputs.s = scalar_vec_to_string_vec(s);
    prover_inputs.rTA = scalar_vec_to_string_vec(rTA);
    prover_inputs.As = scalar_vec_to_string_vec(As);

    let toml_string = toml::to_string(&prover_inputs).expect("Failed to serialize");
    fs::write(config_path, toml_string).expect("Failed to write Prover.toml");
}

/// Delta mode: prove non-keyframe by comparing frame[t] with frame[t-1].
/// Reads current frame from ./Prover.toml, previous frame from the given path.
/// Writes non-keyframe Prover.toml (non_keyframe_edits circuit inputs) to ./Prover.toml.
fn run_delta_mode(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: {} delta <prev_prover_toml_path>", args[0]);
        process::exit(1);
    }

    let current_path = Path::new("Prover.toml");
    let prev_path = Path::new(&args[2]);

    let current_original = load_image(current_path);
    let prev_original = load_image(prev_path);

    let height = current_original.len();
    let width = current_original[0].len();
    println!("Delta mode: {}x{} image", height, width);

    let v_matrix = create_gblur_matrix(height, SIGMA, GBLUR_RADIUS);
    let h_matrix = create_gblur_matrix(width, SIGMA, GBLUR_RADIUS);

    // Blur both frames to compute rT_delta_blur_s outside the circuit.
    println!("Blurring current frame...");
    let current_blurred = apply_gblur(&current_original, &v_matrix, &h_matrix);
    println!("Blurring previous frame...");
    let prev_blurred = apply_gblur(&prev_original, &v_matrix, &h_matrix);

    // Original delta: include ALL non-zero pixel changes (no threshold).
    // A threshold would cause the sparse delta to diverge from the true current-prev difference,
    // breaking the Freivalds equality rTA * delta * As == r * (blur_current - blur_prev) * s.
    println!("Computing original delta batches...");
    let (delta_batches, delta_is, delta_js) =
        compute_delta_batches(&current_original, &prev_original, None);

    // Freivalds vectors: real r^T×A_v and A_h×s
    let r: Vec<Fr> = (0..height).map(|_| gen_rand_scalar()).collect();
    let rTA = vector_matrix_product(&r, &v_matrix);
    let s: Vec<Fr> = (0..width).map(|_| gen_rand_scalar()).collect();
    let As = matrix_vector_product(&h_matrix, &s);

    // Compute rT_delta_blur_s = r^T × (blur(current) - blur(prev)) × s densely outside the circuit.
    // This is O(H×W) Rust computation — no circuit constraints needed.
    // The circuit proves this scalar equals r^T × A × delta_original × s (sparse).
    println!("Computing rT_delta_blur_s (dense, outside circuit)...");
    let rT_delta_blur_s: Fr = (0..height).map(|i| {
        let row_sum: Fr = (0..width).map(|j| {
            (current_blurred[i][j] - prev_blurred[i][j]) * s[j]
        }).sum();
        r[i] * row_sum
    }).sum();

    let delta_inputs = DeltaProverInputs {
        delta_batches: scalar_matrix_to_string_matrix(delta_batches),
        delta_is: scalar_vec_to_string_vec(delta_is),
        delta_js: scalar_matrix_to_string_matrix(delta_js),
        rT_delta_blur_s: format!("{:?}", rT_delta_blur_s),
        r: scalar_vec_to_string_vec(r),
        s: scalar_vec_to_string_vec(s),
        rTA: scalar_vec_to_string_vec(rTA),
        As: scalar_vec_to_string_vec(As),
    };

    let toml_string = toml::to_string(&delta_inputs).expect("Failed to serialize");
    fs::write("Prover.toml", toml_string).expect("Failed to write Prover.toml");
    println!("Non-keyframe Prover.toml written.");
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1].to_lowercase() == "delta" {
        run_delta_mode(&args);
    } else {
        run_keyframe_mode(&args);
    }
}
