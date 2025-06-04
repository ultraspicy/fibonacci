const FILTER_BITS: i32 = 11;
const FILTER_SCALE: i32 = 1 << FILTER_BITS;

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

fn gaussian_kernel1d_fixed_point(sigma: i32, radius: usize) -> Vec<u32> {
    let floating_point_kernel = gaussian_kernel1d(sigma, radius);
    floating_point_kernel
        .iter()
        .map(|x| ((x * 2f64.powf(FILTER_BITS as f64)) as u32))
        .collect::<Vec<u32>>()
}

pub fn build_horizontal_matrix(width: i32, sigma: i32, radius: usize) -> Vec<Vec<i32>> {
    let kernel = gaussian_kernel1d_fixed_point(sigma, radius);
    let kernel_size = kernel.len();
    
    // Create matrix for horizontal convolution
    let mut h = vec![vec![0; width as usize]; width as usize];
    
    // Fill in the matrix based on Gaussian kernel
    for x in 0..width {
        for k in 0..kernel_size {
            let offset = k as i32 - radius as i32;
            let src_pos = x + offset;
            
            // Check bounds
            if src_pos >= 0 && src_pos < width {
                h[src_pos as usize][x as usize] = kernel[k] as i32;
            }
        }
    }
    h
}

pub fn build_vertical_matrix(height: i32, sigma: i32, radius: usize) -> Vec<Vec<i32>> {
    let kernel = gaussian_kernel1d_fixed_point(sigma, radius);
    let kernel_size = kernel.len();
    
    // Create matrix for vertical convolution
    let mut v = vec![vec![0; height as usize]; height as usize];
    
    // Fill in the matrix based on Gaussian kernel
    for y in 0..height {
        for k in 0..kernel_size {
            let offset = k as i32 - radius as i32;
            let src_pos = y + offset;
            
            // Check bounds
            if src_pos >= 0 && src_pos < height {
                v[y as usize][src_pos as usize] = kernel[k] as i32;
            }
        }
    }
    v
}