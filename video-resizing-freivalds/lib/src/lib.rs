pub mod  freivalds_resize;
pub use  freivalds_resize::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use bytemuck::cast_slice;

pub fn u8_to_u32_vec(input: Vec<u8>) -> Vec<u32> {
    assert!(
        input.len() % 4 == 0,
        "Input Vec<u4> length must be a multiple of 8."
    );
    cast_slice(&input).to_vec()
}

pub fn u32_to_u8_vec(vec: Vec<u32>) -> Vec<u8> {
    // Safely reinterpret the slice of u64 as a slice of u8
    cast_slice(&vec).to_vec()
}


pub fn load_image_from_file(input_file: &str) -> Vec<u8> {
    let mut image: Vec<u8> = Vec::new();

    let input_path = Path::new(input_file);
    println!("input_path: {:?}", input_path);
    let file = File::open(&input_path).expect("Failed to open input file");
    let reader = BufReader::new(file);

    for (i, line) in reader.lines().enumerate() {
        match line {
            Ok(line_data) => {
                // Split the line into separate numbers
                for value_str in line_data.split_whitespace() {
                    match value_str.parse::<u8>() {
                        Ok(value) => {
                            image.push(value);
                        }
                        Err(_) => {
                            println!("Error parsing value on line {}: '{}'", i + 1, value_str);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error reading line {}: {:?}", i + 1, e);
            }
        }
    }

    image
}
