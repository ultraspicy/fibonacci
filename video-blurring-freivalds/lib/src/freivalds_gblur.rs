use bytemuck::cast_slice;
use ndarray::Array2;
use rand::{thread_rng, Rng};

fn gaussian_kernel1d(sigma: i32, radius: usize) -> Vec<f64> {
    // Compute sigma squared as f64 for precision
    let sigma2 = (sigma * sigma) as f64;

    // Create a vector to hold the Gaussian kernel
    let mut kernel = Vec::new();

    // Generate values from -radius to +radius
    for x in -(radius as i32)..=(radius as i32) {
        let value = (-0.5 / sigma2 * (x as f64).powi(2)).exp();
        kernel.push(value);
    }

    // Normalize the kernel so that it sums to 1
    let sum: f64 = kernel.iter().sum();
    kernel.iter_mut().for_each(|x| *x /= sum);

    kernel
}

fn gaussian_kernel1d_fixed_point(
    sigma: i32,
    radius: usize,
    fractional_component: usize,
) -> Vec<u64> {
    let floating_point_kernel = gaussian_kernel1d(sigma, radius);
    floating_point_kernel
        .iter()
        .map(|x| ((x * 2f64.powf(fractional_component as f64)) as u64))
        .collect::<Vec<u64>>()
}

// Blurs a row or column depending on whether it is left or right multiplied.
fn blur_matrix(kernel: &[u64], height: usize) -> Array2<u64> {
    let mut matrix = Array2::<u64>::zeros((height, height));
    let radius = (kernel.len() - 1) / 2;
    let one_side_sum: u64 = kernel[0..radius].iter().sum();

    for row in 0..height {
        let filter_center = row;
        // The contents of `kernel` will be "pasted" in between start_idx and end_idx.
        // If the filter is too wide, remaining "mass" will be given to the start/end of the row.
        // (this is done in some contexts in ffmpeg already)
        let start_idx = if filter_center < radius {
            0
        } else {
            filter_center - radius
        };
        let end_idx = if height - 1 < (filter_center + radius) {
            height - 1
        } else {
            filter_center + radius
        };

        matrix[[row, filter_center]] = kernel[radius];

        let mut remaining_left_mass = one_side_sum;
        if start_idx == filter_center {
            matrix[[row, filter_center]] += remaining_left_mass;
        } else {
            let mut col_index = filter_center - 1;
            let mut filter_index = radius - 1;
            while col_index > start_idx {
                matrix[[row, col_index]] = kernel[filter_index];
                remaining_left_mass -= kernel[filter_index];
                col_index -= 1;
                filter_index -= 1;
            }
            matrix[[row, col_index]] += remaining_left_mass;
        }

        let mut remaining_right_mass = one_side_sum;
        if end_idx == filter_center {
            matrix[[row, filter_center]] += remaining_right_mass;
        } else {
            let mut col_index = filter_center + 1;
            let mut filter_index = radius + 1;
            while col_index < end_idx {
                matrix[[row, col_index]] = kernel[filter_index];
                remaining_right_mass -= kernel[filter_index];
                col_index += 1;
                filter_index += 1;
            }
            matrix[[row, col_index]] += remaining_right_mass;
        }
    }

    matrix
}

// TODO(sashafrolov): Redo this with bytemuck so we can do this faster.
pub fn u64_to_u8_vec(vec: Vec<u64>) -> Vec<u8> {
    // Safely reinterpret the slice of u64 as a slice of u8
    cast_slice(&vec).to_vec()
}

pub fn u8_to_u64_vec(input: Vec<u8>) -> Vec<u64> {
    assert!(
        input.len() % 8 == 0,
        "Input Vec<u8> length must be a multiple of 8."
    );
    cast_slice(&input).to_vec()
}

pub fn freivalds_prover(
    sigma: i32,
    radius: usize,
    image_width: usize,
    image_height: usize,
    src: &[u8],
) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
    let gaussian_kernel = gaussian_kernel1d_fixed_point(sigma, radius, 24);
    let freivalds_matrix_left = blur_matrix(&gaussian_kernel, image_height);
    let freivalds_matrix_right = blur_matrix(&gaussian_kernel, image_width);

    let src_u64: Vec<u64> = src.iter().map(|x| *x as u64).collect();
    println!("{}, {}", image_height, image_width);
    let src_matrix = Array2::from_shape_vec((image_height, image_width), src_u64).unwrap();
    // Intermediate Results
    let vertically_blurred_channel = freivalds_matrix_left.dot(&src_matrix);
    let horizontally_blurred_channel = vertically_blurred_channel.dot(&freivalds_matrix_right);
    // Final Result
    let channel_blurred = horizontally_blurred_channel.flatten().to_vec();

    let mut rng = thread_rng();
    let freivalds_randomness_left: Vec<u64> = (0..image_height).map(|_| rng.gen()).collect();
    let freivalds_randomness_left_ndarray =
        Array2::from_shape_vec((1, image_height), freivalds_randomness_left.clone()).unwrap();
    let freivalds_randomness_right: Vec<u64> = (0..image_width).map(|_| rng.gen()).collect();
    let freivalds_randomness_right_ndarray =
        Array2::from_shape_vec((image_width, 1), freivalds_randomness_right.clone()).unwrap();

    let r_left_t_b = freivalds_randomness_left_ndarray.dot(&freivalds_matrix_left);
    let b_r_right = freivalds_matrix_right.dot(&freivalds_randomness_right_ndarray);
    (
        freivalds_randomness_left,
        freivalds_randomness_right,
        r_left_t_b.flatten().to_vec(),
        b_r_right.flatten().to_vec(),
        channel_blurred,
    )
}

pub fn freivalds_verifier(
    freivalds_randomness_left: Vec<u64>,
    freivalds_randomness_right: Vec<u64>,
    r_left_t_b: Vec<u64>,
    b_r_right: Vec<u64>,
    src: &[u8],
    channel_blurred: &[u64],
    image_height: usize,
    image_width: usize,
) {
    println!("cycle-tracker-start: first asserts");
    if freivalds_randomness_left.len() != image_height {
        panic!("Left Freivald's randomness has incorrect length");
    }
    if freivalds_randomness_right.len() != image_width {
        panic!("Right Freivald's randomness has incorrect length");
    }
    if r_left_t_b.len() != image_height {
        panic!("Left partial matrix product has incorrect length");
    }
    if b_r_right.len() != image_width {
        panic!("Right partial matrix product has incorrect length");
    }
    println!("cycle-tracker-end: first asserts");

    println!("cycle-tracker-start: first loop");
    // Inner product for non-blurred image
    println!(
        "Image width: {}, image height: {}",
        image_width, image_height
    );
    // let goldilocks_prime: u128 = (1u128 << 64) - (1u128 << 32) + 1;
    let mersenne31 = (1u64 << 31) - 1;
    let mut r_left_t_b_channel: Vec<u64> = vec![0; image_width];
    for i in 0..image_height {
        for j in 0..image_width {
            let old_val = r_left_t_b_channel[j];
            let coeff = r_left_t_b[i];
            let matrix_val = src[i * image_width + j] as u64;
            r_left_t_b_channel[j] = (old_val + coeff * matrix_val);
        }
    }
    println!("cycle-tracker-end: first loop");

    println!("cycle-tracker-start: first inner");
    let mut inner_product_left = 0u64;
    for i in 0..image_width {
        let coeff = r_left_t_b_channel[i];
        let randomness = b_r_right[i];
        inner_product_left = (inner_product_left + (coeff * randomness));
    }
    println!("cycle-tracker-end: first inner");

    println!("cycle-tracker-start: second loop");
    // Inner product for blurred image
    let mut r_left_r_blur_product: Vec<u64> = vec![0; image_width];
    for i in 0..image_height {
        for j in 0..image_width {
            let old_val = r_left_r_blur_product[j];
            let coeff = freivalds_randomness_left[i];
            let matrix_val = channel_blurred[i * image_width + j];
            r_left_r_blur_product[j] = (old_val + coeff * matrix_val);
        }
    }
    println!("cycle-tracker-end: second loop");

    println!("cycle-tracker-start: second inner");
    let mut inner_product_right = 0u64;
    for i in 0..image_width {
        let coeff = r_left_r_blur_product[i];
        let randomness = freivalds_randomness_right[i];
        inner_product_right = (inner_product_right + (coeff * randomness));
    }
    println!("cycle-tracker-end: second inner");

    if (inner_product_left as u64) != (inner_product_right as u64) {
        println!("Freivalds verification failed");
    }
    println!(
        "left: {}, right: {}",
        inner_product_left, inner_product_right
    )
}