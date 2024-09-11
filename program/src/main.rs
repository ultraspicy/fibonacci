//! Original goal: we want to prove the resulting image is the output of original image using ffmpeg
//! 
//! This is difficult since ffmpeg has system-specifc implementation, so it is not always 
//! reproducible. Instead we have implemented our own simplified ffmpeg algothrim that mimics ffmpeg. 
//! Under such, we not only need to prove that the output is indeed processed result of original 
//! image, we also  need to prove the output of ffmeg (outpu1) and output of our own (output2) 
//! are close enough.
//! 
//! "Close enough" can be defined in various way, either statitically or from pixel-by-pixel 
//! comparison. Under our scenario of resizing image, the mathmatical contraints are 
//!   - L_INF norm of all pixels (in two u8 vector) is less than X
//!   - TODO Add more here
//! 
//! public input 
//!   - Hash of the original signed image
//!   - Hash of the transformed image using ffmpeg
//!   - (out of scope)verification key of the signed original image (coming from device?)
//! 
//! private input
//!   - The original signed image
//!   - The details of image processing logic (params, sequence etc that implemented in code)
//!   - the resulting transformed image
//! 
//! Proof:
//!   - the transformed image is the output of original image after our own processing
//!   - output of our own resizing is "close" enough
//!   - L_inf norm of the full image is winthin the range

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::cmp::{min, max};
use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct, print_data_sample, print_image_summary};

pub fn main() {
    // Read an input to the program.
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        println!("Usage: {} <input_file> <input_width> <input_height> <output_file> <output_width> <output_height>", args[0]);
        return;
    }
    let input_file = &args[1];
    let input_width = args[2].parse::<i32>().unwrap();
    let input_height = args[3].parse::<i32>().unwrap();
    // let output_file = &args[4];
    // let output_width = args[5].parse::<i32>().unwrap();
    // let output_height = args[6].parse::<i32>().unwrap();

    let input_path = Path::new(input_file);
    let file = File::open(&input_path).expect("Failed to open input file");
    let reader = BufReader::new(file);

    let mut input: Vec<u8> = Vec::new(); 
    for (i, line) in reader.lines().enumerate() {
        match line {
            Ok(line_data) => {
                // Split the line into separate numbers
                for value_str in line_data.split_whitespace() {
                    match value_str.parse::<u8>() {
                        Ok(value) => {
                            input.push(value);
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

    println!("Original image:");
    print_image_summary(input_width as usize, input_height as usize, &input);
    print_data_sample(&input, 64);

    // // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // // from the prover.
    // let n = sp1_zkvm::io::read::<u32>();

    // // Compute the n'th fibonacci number using a function from the workspace lib crate.
    // let (a, b) = fibonacci(n);

    // // Encode the public values of the program.
    // let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { n, a, b });

    // // Commit to the public values of the program. The final proof will have a commitment to all the
    // // bytes that were committed to.
    // sp1_zkvm::io::commit_slice(&bytes);
}
