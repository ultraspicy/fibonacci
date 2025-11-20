use ark_bn254::Fr;
use ark_ff::Field;
use ark_ff::{One, Zero};
use rand::Rng;
use std::env;
use std::process;
use std::time::Instant;

const IMAGE_HEIGHT: usize = 720;
const IMAGE_WIDTH: usize = 1280;

const SIGMA: f64 = 10.0;
const GBLUR_RADIUS: usize = 30;
const KERNEL_SCALE: u64 = 1u64 << 32;
const FILTER_BITS: usize = 16;

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

fn scalar_vec_to_string_vec(v: &[Fr]) -> Vec<String> {
    v.iter().map(|x| format!("{:?}", x)).collect()
}

fn create_diagonal_band_matrix(size: usize, band_width: usize) -> Vec<Vec<Fr>> {
    assert!(size > 0, "Matrix size must be positive");
    assert!(band_width > 0, "Band width must be positive");

    let band_width = band_width.min(size);
    let left = band_width / 2;
    let right = band_width - left - 1;
    let mut matrix = vec![vec![Fr::zero(); size]; size];
    let band_value = Fr::from((1u64 << 40) - 1); // doing this so matrix multiplication times
                                                 // Are reflective of reasonably large values.

    for i in 0..size {
        let start = i.saturating_sub(left);
        let end = (i + right).min(size - 1);
        for j in start..=end {
            matrix[i][j] = band_value;
        }
    }

    matrix
}

fn create_resizing_matrix(src_size: usize, dst_size: usize, for_horizontal: bool) -> Vec<Vec<Fr>> {
    let matrix = create_resize_matrix_impl(src_size, dst_size);
    if for_horizontal {
        transpose(matrix)
    } else {
        matrix
    }
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
            let coeff_u64 = if j == 0 {
                (1u64 << FILTER_BITS) - (xx as u64)
            } else {
                xx as u64
            };

            let src_idx = src_pos + j;
            if src_idx < src_size {
                matrix[i][src_idx] = Fr::from(coeff_u64);
            }
        }
    }

    matrix
}

fn transpose(matrix: Vec<Vec<Fr>>) -> Vec<Vec<Fr>> {
    let rows = matrix.len();
    if rows == 0 {
        return vec![];
    }
    let cols = matrix[0].len();

    let mut transposed = vec![vec![Fr::zero(); rows]; cols];
    for i in 0..rows {
        for j in 0..cols {
            transposed[j][i] = matrix[i][j];
        }
    }
    transposed
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

fn create_gblur_matrix(size: usize, sigma: f64, radius: usize) -> Vec<Vec<Fr>> {
    assert!(size > 0, "Matrix size must be positive");
    assert!(radius > 0, "Kernel radius must be positive");
    assert!(sigma > 0.0, "Sigma must be positive");

    let mut matrix = vec![vec![Fr::zero(); size]; size];
    let kernel = gaussian_kernel1d_fixed_point(sigma, radius as i32);
    let kernel_len = kernel.len();
    assert_eq!(kernel_len, 2 * radius + 1, "Kernel length mismatch");

    for i in 0..size {
        let left_overflow = if i < radius { radius - i } else { 0 };
        let right_overflow = if i + radius >= size {
            i + radius - size + 1
        } else {
            0
        };

        let left_mass: Fr = (0..left_overflow)
            .map(|j| kernel[j])
            .fold(Fr::zero(), |acc, x| acc + x);

        let right_mass: Fr = (kernel_len - right_overflow..kernel_len)
            .map(|j| kernel[j])
            .fold(Fr::zero(), |acc, x| acc + x);

        for (k_idx, j) in (i.saturating_sub(radius)..=(i + radius).min(size - 1)).enumerate() {
            let kernel_offset = left_overflow + k_idx;
            matrix[i][j] = kernel[kernel_offset];
        }

        if left_overflow > 0 {
            matrix[i][0] += left_mass;
        }

        if right_overflow > 0 {
            matrix[i][size - 1] += right_mass;
        }
    }

    matrix
}

fn create_matrix(matrix_type: MatrixType, size: usize, need_transpose: bool) -> Vec<Vec<Fr>> {
    match matrix_type {
        MatrixType::Tridiagonal => create_diagonal_band_matrix(size, 7),
        MatrixType::Resizing => create_resizing_matrix(size, size / 2, need_transpose),
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

fn matrix_vector_product(a: &[Vec<Fr>], v: &[Fr]) -> Vec<Fr> {
    let height = a.len();
    assert!(height > 0);
    let width = a[0].len();
    assert!(width == v.len());

    let mut output = Vec::with_capacity(height);
    for i in 0..height {
        let mut inner_prod = Fr::zero();
        for j in 0..width {
            inner_prod += a[i][j] * v[j];
        }
        output.push(inner_prod);
    }
    output
}

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

fn main() {
    let args: Vec<String> = env::args().collect();
    let matrix_type = if args.len() > 1 {
        match parse_matrix_type(&args[1]) {
            Ok(mt) => mt,
            Err(e) => {
                eprintln!("Error: {}", e);
                eprintln!(
                    "Usage: {} [matrix_type] where matrix_type is tridiagonal (default), resizing, or gblur",
                    args[0]
                );
                process::exit(1);
            }
        }
    } else {
        MatrixType::Tridiagonal
    };

    let adjust_factor = match matrix_type {
        MatrixType::Resizing => 2,
        _ => 1,
    };

    assert!(
        IMAGE_HEIGHT % adjust_factor == 0 && IMAGE_WIDTH % adjust_factor == 0,
        "Image dimensions must be divisible by {} for {:?}",
        adjust_factor,
        matrix_type
    );

    println!("Using matrix type: {:?}", matrix_type);
    println!(
        "Image dimensions: {} × {} (height × width)",
        IMAGE_HEIGHT, IMAGE_WIDTH
    );

    let start = Instant::now();

    let horizontal_edit_matrix = create_matrix(matrix_type, IMAGE_WIDTH, true);
    let vertical_edit_matrix = create_matrix(matrix_type, IMAGE_HEIGHT, false);

    let r: Vec<_> = (0..IMAGE_HEIGHT / adjust_factor)
        .map(|_| gen_rand_scalar())
        .collect();
    let rTA = vector_matrix_product(&r, &vertical_edit_matrix);

    let s: Vec<_> = (0..IMAGE_WIDTH / adjust_factor)
        .map(|_| gen_rand_scalar())
        .collect();
    let As = matrix_vector_product(&horizontal_edit_matrix, &s);

    let duration = start.elapsed();

    println!("Computation time (excluding output): {:.2?}", duration);
    // println!("r (len {}): {:?}", r.len(), scalar_vec_to_string_vec(&r));
    // println!("s (len {}): {:?}", s.len(), scalar_vec_to_string_vec(&s));
    // println!(
    //     "rTA (len {}): {:?}",
    //     rTA.len(),
    //     scalar_vec_to_string_vec(&rTA)
    // );
    // println!("As (len {}): {:?}", As.len(), scalar_vec_to_string_vec(&As));
}
