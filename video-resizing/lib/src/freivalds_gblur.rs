use fixed::{traits::Fixed, types::extra::U32, FixedU64};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sprs::{linalg::ordering::start, CsMat, CsVec, TriMat};

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

fn gaussian_kernel1d_fixed_point(sigma: i32, radius: usize) -> Vec<u64> {
    let floating_point_kernel = gaussian_kernel1d(sigma, radius);
    floating_point_kernel
        .iter()
        .map(|x| ((x * 2f64.powf(32.0)) as u64))
        .collect::<Vec<u64>>()
}

fn freivalds_matrix(kernel: Vec<u64>, height: usize, width: usize) -> CsMat<u64> {
    let numpixels = height * width;
    let mut matrix = TriMat::new((numpixels, numpixels));
    let radius = (kernel.len() - 1) / 2;
    let one_side_sum = kernel[0..radius].iter().sum();

    for pixel in 0..(numpixels as isize) {
        let (row, col) = (pixel / (width as isize), pixel % (width as isize));
        let mut start_idx = pixel - (radius as isize);
        let row_start = row * (width as isize);
        if row_start > start_idx {
            start_idx = row_start;
        }
        let mut end_idx = pixel + (radius as isize);
        let row_end = (row + 1) * (width as isize) - 1;
        if row_end < end_idx {
            end_idx = row_end;
        }

        matrix.add_triplet(pixel as usize, pixel as usize, kernel[radius]);

        let mut remaining_left_mass = one_side_sum;
        if start_idx == pixel {
            let triplet_index = matrix.find_locations(pixel as usize, pixel as usize);
            matrix.set_triplet(
                triplet_index[0],
                pixel as usize,
                pixel as usize,
                kernel[radius] + remaining_left_mass,
            );
        } else {
            let mut col_index = pixel - 1;
            let mut filter_index = radius - 1;
            while col_index > start_idx {
                matrix.add_triplet(pixel as usize, col_index as usize, kernel[filter_index]);
                remaining_left_mass -= kernel[filter_index];
                col_index -= 1;
                filter_index -= 1;
            }
            matrix.add_triplet(pixel as usize, col_index as usize, remaining_left_mass);
        }

        let mut remaining_right_mass = one_side_sum;
        if end_idx == pixel {
            let triplet_index = matrix.find_locations(pixel as usize, pixel as usize);
            matrix.set_triplet(
                triplet_index[0],
                pixel as usize,
                pixel as usize,
                kernel[radius] + remaining_right_mass,
            );
        } else {
            let mut col_index = pixel + 1;
            let mut filter_index = radius + 1;
            while col_index < end_idx {
                matrix.add_triplet(pixel as usize, col_index as usize, kernel[filter_index]);
                remaining_right_mass -= kernel[filter_index];
                col_index += 1;
                filter_index += 1;
            }
            matrix.add_triplet(pixel as usize, col_index as usize, remaining_right_mass);
        }
    }

    matrix.to_csr()
}

pub fn u64_to_u8_vec(input: &[u64]) -> Vec<u8> {
    // Use unsafe to reinterpret the slice of u64 as a slice of u8
    unsafe {
        let ptr = input.as_ptr() as *const u8; // Pointer to the start of the u64 slice as u8
        let len = input.len() * 8; // Each u64 is 8 bytes
        std::slice::from_raw_parts(ptr, len).to_vec() // Create a Vec<u8> from the slice
    }
}

pub fn u8_to_u64_vec(input: Vec<u8>) -> Vec<u64> {
    // Ensure the input length is a multiple of 8
    assert!(
        input.len() % 8 == 0,
        "Input Vec<u8> length must be a multiple of 8"
    );

    // Perform the reinterpretation using unsafe
    unsafe {
        let ptr = input.as_ptr() as *const u64; // Reinterpret as a pointer to u64
        let len = input.len() / 8; // Calculate the number of u64 elements
        std::slice::from_raw_parts(ptr, len).to_vec() // Create a Vec<u64> from the slice
    }
}

pub fn freivalds_prover(
    sigma: i32,
    radius: usize,
    image_width: usize,
    image_height: usize,
    src: &[u8],
) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    let gaussian_kernel = gaussian_kernel1d_fixed_point(sigma, radius);
    let freivalds_matrix = freivalds_matrix(gaussian_kernel, image_height, image_width);

    let src_vector = CsVec::new(
        src.len(),
        (0..src.len()).collect(),
        src.into_iter().map(|x| *x as u64).collect(),
    );

    let channel_blurred_sparse = &freivalds_matrix * &src_vector;
    let channel_blurred = channel_blurred_sparse
        .to_dense()
        .to_vec()
        .into_iter()
        .map(|x| (x >> 32) as u8)
        .collect();
    let mut rng = thread_rng();
    let freivalds_randomness: Vec<u64> = (0..src.len()).map(|_| rng.gen()).collect();
    let random_vector = CsVec::new(
        freivalds_randomness.len(),
        (0..freivalds_randomness.len()).collect(),
        freivalds_randomness.clone(),
    );

    let channel_t_c = &freivalds_matrix.transpose_into() * &random_vector;
    (
        freivalds_randomness,
        channel_t_c.to_dense().to_vec(),
        channel_blurred,
    )
}

pub fn freivalds_verifier(
    freivalds_randomness: Vec<u64>,
    channel_t_c: Vec<u64>,
    src: &[u8],
    channel_blurred: &[u8],
) {
    if freivalds_randomness.len() != channel_blurred.len() {
        panic!("Vector lengths are wrong");
    }
    if channel_t_c.len() != src.len() {
        panic!("Vector lengths are wrong");
    }
    let dot_product_1: u64 = freivalds_randomness
        .iter()
        .zip(channel_blurred.iter())
        .map(|(x, y)| ((*x) * (*y as u64)))
        .sum();
    let dot_product_2: u64 = channel_t_c
        .iter()
        .zip(src.iter())
        .map(|(x, y)| ((*x) * (*y as u64)))
        .sum();

    if (dot_product_1 != dot_product_2) {
        println!("Verification failed!");
    }
}
