use ark_bn254::Fr;
use ark_ff::Field;
use ark_ff::{One, Zero};
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

#[derive(Debug, Clone, Copy)]
enum MatrixType {
    Tridiagonal,
    Resizing,
    GBlur,
}

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

// Inner product of two vectors
fn inner_product(u: &[Fr], v: &[Fr]) -> Fr {
    let len = u.len();
    assert!(len > 0);
    assert!(len == v.len(), "Vectors must have the same length");

    let mut result = Fr::zero();
    for i in 0..len {
        result += u[i] * v[i];
    }
    result
}

// Matrix-vector product Av
fn matrix_vector_product(a: &[Vec<Fr>], v: &[Fr]) -> Vec<Fr> {
    let height = a.len();
    assert!(height > 0);
    let width = a[0].len();
    assert!(width == v.len());
    let mut output = Vec::new();
    for i in 0..height {
        let mut inner_prod = Fr::zero();
        for j in 0..width {
            inner_prod += a[i][j] * v[j];
        }
        output.push(inner_prod);
    }
    output
}

// vector matrix product (v^T)A
fn vector_matrix_product(v: &[Fr], a: &[Vec<Fr>]) -> Vec<Fr> {
    let height = a.len();
    assert!(height > 0);
    assert!(height == v.len());
    let width = a[0].len();
    let mut output = vec![Fr::zero(); width];
    for i in 0..height {
        for j in 0..width {
            output[j] += a[i][j] * v[i];
        }
    }
    output
}

// Matrix-matrix product AB where A is a band matrix (parallelized)
// A has band structure: non-zero entries within kernel_width of diagonal
// B can be any matrix
fn matrix_matrix_product_band_left(
    a: &[Vec<Fr>],
    b: &[Vec<Fr>],
    kernel_width: usize,
) -> Vec<Vec<Fr>> {
    let a_height = a.len();
    assert!(a_height > 0);
    let a_width = a[0].len();

    let b_height = b.len();
    assert!(b_height > 0);
    let b_width = b[0].len();

    assert!(
        a_width == b_height,
        "Matrix dimensions incompatible for multiplication"
    );

    // Process rows in parallel
    a.par_iter()
        .enumerate()
        .map(|(i, a_row)| {
            let mut row = vec![Fr::zero(); b_width];

            // For row i of A, non-zero entries are in columns [i-kernel_width, i+kernel_width]
            let k_start = i.saturating_sub(kernel_width);
            let k_end = (i + kernel_width + 1).min(a_width);

            for j in 0..b_width {
                let mut inner_prod = Fr::zero();

                // Only iterate over the band where A[i][k] is non-zero
                for k in k_start..k_end {
                    inner_prod += a_row[k] * b[k][j];
                }

                row[j] = inner_prod;
            }
            row
        })
        .collect()
}

// Matrix-matrix product AB where B is a band matrix (parallelized)
// A can be any matrix
// B has band structure: non-zero entries within kernel_width of diagonal
fn matrix_matrix_product_band_right(
    a: &[Vec<Fr>],
    b: &[Vec<Fr>],
    kernel_width: usize,
) -> Vec<Vec<Fr>> {
    let a_height = a.len();
    assert!(a_height > 0);
    let a_width = a[0].len();

    let b_height = b.len();
    assert!(b_height > 0);
    let b_width = b[0].len();

    assert!(
        a_width == b_height,
        "Matrix dimensions incompatible for multiplication"
    );

    // Process rows in parallel
    a.par_iter()
        .map(|a_row| {
            let mut row = vec![Fr::zero(); b_width];

            for j in 0..b_width {
                let mut inner_prod = Fr::zero();

                // For column j of B, non-zero entries are in rows [j-kernel_width, j+kernel_width]
                let k_start = j.saturating_sub(kernel_width);
                let k_end = (j + kernel_width + 1).min(b_height);

                // Only iterate over the band where B[k][j] is non-zero
                for k in k_start..k_end {
                    inner_prod += a_row[k] * b[k][j];
                }

                row[j] = inner_prod;
            }
            row
        })
        .collect()
}

// Creates a matrix with 1's on main diagonal and adjacent diagonals
// This is a simple test matrix that I used for debugging and benchmarking.
fn create_tridiagonal_matrix(size: usize) -> Vec<Vec<Fr>> {
    assert!(size > 0, "Matrix size must be positive");

    let mut matrix = vec![vec![Fr::zero(); size]; size];

    for i in 0..size {
        // Main diagonal
        matrix[i][i] = Fr::one();

        // Upper diagonal (if not in last row)
        if i + 1 < size {
            matrix[i][i + 1] = Fr::one();
        }

        // Lower diagonal (if not in first row)
        if i > 0 {
            matrix[i][i - 1] = Fr::one();
        }
    }

    matrix
}

fn create_resizing_matrix(_size: usize) -> Vec<Vec<Fr>> {
    unimplemented!("Resizing matrix not yet implemented");
}

fn gaussian_kernel1d(sigma: f64, radius: i32) -> Vec<f64> {
    let sigma2 = sigma * sigma;
    let x: Vec<f64> = (-radius..=radius).map(|i| i as f64).collect();

    let mut phi_x: Vec<f64> = x
        .iter()
        .map(|&xi| (-0.5 / sigma2 * xi * xi).exp())
        .collect();

    let sum: f64 = phi_x.iter().sum();
    phi_x.iter_mut().for_each(|val| *val /= sum);

    phi_x
}

fn gaussian_kernel1d_fixed_point(sigma: f64, radius: i32) -> Vec<Fr> {
    let fp_kernel = gaussian_kernel1d(sigma, radius);
    fp_kernel
        .iter()
        .map(|&x| Fr::from((x * KERNEL_SCALE as f64) as u64))
        .collect()
}

// Size is the width/height of the matrix, radius is the radius of the kernel to generate.
fn create_gblur_matrix(size: usize, sigma: f64, radius: usize) -> Vec<Vec<Fr>> {
    assert!(size > 0, "Matrix size must be positive");
    assert!(radius > 0, "Kernel radius must be positive");
    assert!(sigma > 0.0, "Sigma must be positive");

    let mut matrix = vec![vec![Fr::zero(); size]; size];
    let kernel = gaussian_kernel1d_fixed_point(sigma, radius as i32);
    let kernel_len = kernel.len();

    // kernel_len should be 2*radius + 1
    assert_eq!(kernel_len, 2 * radius + 1, "Kernel length mismatch");

    // For each row of the matrix
    for i in 0..size {
        // Calculate which kernel elements can fit within the matrix bounds
        let left_overflow = if i < radius { radius - i } else { 0 };
        let right_overflow = if i + radius >= size {
            i + radius - size + 1
        } else {
            0
        };

        // Sum of mass that would fall outside the left edge
        let left_mass: Fr = (0..left_overflow)
            .map(|j| kernel[j].clone())
            .fold(Fr::zero(), |acc, x| acc + x);

        // Sum of mass that would fall outside the right edge
        let right_mass: Fr = (kernel_len - right_overflow..kernel_len)
            .map(|j| kernel[j].clone())
            .fold(Fr::zero(), |acc, x| acc + x);

        // Place kernel values along the row
        for (k_idx, j) in (i.saturating_sub(radius)..=(i + radius).min(size - 1)).enumerate() {
            let kernel_offset = left_overflow + k_idx;
            matrix[i][j] = kernel[kernel_offset].clone();
        }

        // Add the overflow mass to the edge elements
        if left_overflow > 0 {
            // Add left overflow mass to the leftmost element in this row
            matrix[i][0] = matrix[i][0].clone() + left_mass;
        }

        if right_overflow > 0 {
            // Add right overflow mass to the rightmost element in this row
            matrix[i][size - 1] = matrix[i][size - 1].clone() + right_mass;
        }
    }

    matrix
}

fn create_matrix(matrix_type: MatrixType, size: usize) -> Vec<Vec<Fr>> {
    match matrix_type {
        MatrixType::Tridiagonal => create_tridiagonal_matrix(size),
        MatrixType::Resizing => create_resizing_matrix(size),
        MatrixType::GBlur => create_gblur_matrix(size, SIGMA, GBLUR_RADIUS),
    }
}

fn parse_matrix_type(s: &str) -> Result<MatrixType, String> {
    match s.to_lowercase().as_str() {
        "tridiagonal" => Ok(MatrixType::Tridiagonal),
        "resizing" => Ok(MatrixType::Resizing),
        "gblur" => Ok(MatrixType::GBlur),
        _ => Err(format!(
            "Invalid matrix type '{}'. Valid options are: tridiagonal, resizing, gblur",
            s
        )),
    }
}

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    let matrix_type = if args.len() > 1 {
        match parse_matrix_type(&args[1]) {
            Ok(mt) => mt,
            Err(e) => {
                eprintln!("Error: {}", e);
                eprintln!("Usage: {} [matrix_type]", args[0]);
                eprintln!("  matrix_type: tridiagonal (default), resizing, or gblur");
                process::exit(1);
            }
        }
    } else {
        MatrixType::Tridiagonal // Default
    };

    println!("Using matrix type: {:?}", matrix_type);

    let config_path = Path::new("Prover.toml");

    if !config_path.exists() {
        eprintln!("Error: {} does not exist.", config_path.display());
        process::exit(1);
    }

    // Read and parse TOML file
    let contents = fs::read_to_string(config_path).expect("Failed to read Prover.toml");

    let mut prover_inputs: ProverInputs = toml::from_str(&contents).expect("Failed to parse TOML");

    let image_height = prover_inputs.original_image.len();
    let image_width = prover_inputs.original_image[0].len();

    let mut rng = rand::thread_rng();

    // Generate random image
    let random_image: Vec<Vec<_>> = (0..image_height)
        .map(|_| {
            (0..image_width)
                .map(|_| gen_scalar(rng.gen_range(0..=255)))
                .collect()
        })
        .collect();

    let horizontal_blur_matrix = create_matrix(matrix_type, image_width);
    let vertical_blur_matrix = create_matrix(matrix_type, image_height);

    // Note: gblurr radius is an upper bound on the kernel radius to speed up the matrix math.
    let row_wise_blurred_image =
        matrix_matrix_product_band_left(&vertical_blur_matrix, &random_image, GBLUR_RADIUS);
    let blurred_image = matrix_matrix_product_band_right(
        &row_wise_blurred_image,
        &horizontal_blur_matrix,
        GBLUR_RADIUS,
    );

    let target_middle_image = blurred_image.clone();
    let edited_image = blurred_image.clone();

    let r: Vec<_> = (0..image_height).map(|_| gen_rand_scalar()).collect();

    let rTA = vector_matrix_product(&r, &vertical_blur_matrix);

    let s: Vec<_> = (0..image_width).map(|_| gen_rand_scalar()).collect();

    let As = matrix_vector_product(&horizontal_blur_matrix, &s);

    // Do Freivald's verification for sanity check, etc.
    let rTAI = vector_matrix_product(&rTA, &random_image);
    let rTAIAs = inner_product(&rTAI, &As);

    let rTF = vector_matrix_product(&r, &target_middle_image);
    let rTFs = inner_product(&rTF, &s);

    println!("LHS: {:?}", rTAIAs);
    println!("RHS: {:?}", rTFs);

    // Update prover_inputs
    prover_inputs.original_image = scalar_matrix_to_string_matrix(random_image);
    prover_inputs.target_middle_image = scalar_matrix_to_string_matrix(target_middle_image);
    prover_inputs.edited_image = scalar_matrix_to_string_matrix(edited_image);
    prover_inputs.r = scalar_vec_to_string_vec(r);
    prover_inputs.s = scalar_vec_to_string_vec(s);
    prover_inputs.rTA = scalar_vec_to_string_vec(rTA.clone());
    prover_inputs.As = scalar_vec_to_string_vec(As.clone());

    // Serialize and write back to file
    let toml_string = toml::to_string(&prover_inputs).expect("Failed to serialize to TOML");

    fs::write(config_path, toml_string).expect("Failed to write to Prover.toml");
}
