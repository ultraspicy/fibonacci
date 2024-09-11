use alloy_sol_types::sol;
use std::cmp::{min, max};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}

/// demo image processing
pub fn demo_processing(image: &[u8]) -> Vec<u8> {
    image.iter().map(|&x| x.wrapping_add(1)).collect()
}

pub fn print_data_sample(data: &[u8], sample_size: usize) {
    println!("Data sample (first {} values):", sample_size);
    for (i, &value) in data.iter().take(sample_size).enumerate() {
        print!("{:3} ", value);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();
}

pub fn print_image_summary(width: usize, height: usize, data: &[u8]) {
    let mut sum: u64 = 0;
    let mut min_val: u8 = 255;
    let mut max_val: u8 = 0;

    for &pixel in data.iter() {
        sum += pixel as u64;
        min_val = min(min_val, pixel);
        max_val = max(max_val, pixel);
    }

    let avg = sum as f64 / (width * height) as f64;

    println!("Image Summary ({}x{}):", width, height);
    println!("Min value: {}", min_val);
    println!("Max value: {}", max_val);
    println!("Average value: {:.2}", avg);
}