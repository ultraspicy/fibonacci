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

use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use std::cmp::{max, min};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let image: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();

    // Write n to public input
    //sp1_zkvm::io::commit(&image);
    sp1_zkvm::io::commit(&image[0]);
    sp1_zkvm::io::commit(&image[1]);

    print!("image data: {:?}", image);

    // Compute the n'th fibonacci number, using normal Rust code.
    // let mut a = 0;
    // let mut b = 1;
    // for _ in 0..n {
    //     let mut c = a + b;
    //     c %= 7919; // Modulus to prevent overflow.
    //     a = b;
    //     b = c;
    // }

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a system call which handles writing
    // outputs to the prover.
    // sp1_zkvm::io::commit(&a);
    // sp1_zkvm::io::commit(&b);
}
