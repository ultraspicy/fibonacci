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
use fibonacci_lib::{fibonacci, PublicValuesStruct, Context};
use std::cmp::{max, min};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;



pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let c = sp1_zkvm::io::read::<Context>();
    let image: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let target_image: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();

    let mut tmp = vec![0u8; c.dst_w as usize * c.src_h as usize];
    let mut dst = vec![0u8; c.dst_w as usize * c.dst_h as usize];

    // hard code here
    const FILTER_BITS: i32 = 14;
    const FILTER_SCALE: i32 = 1 << FILTER_BITS;


    // Horizontal scaling
    for y in 0..c.src_h as usize {
        for x in 0..c.dst_w as usize {
            let src_pos = c.filter_pos[x];
            let mut val = 0;

            for z in 0..c.filter_size {
                if src_pos + (z as i32) < c.src_w {
                    val += image[y * c.src_w as usize + (src_pos as usize + z)] as u32
                        * c.filter[x * c.filter_size + z] as u32;
                }
            }

            tmp[y * c.dst_w as usize + x] = ((val + (1 << (FILTER_BITS - 1))) >> FILTER_BITS) as u8;
        }
    }

    // Vertical scaling
    for y in 0..c.dst_h as usize {
        for x in 0..c.dst_w as usize {
            let src_pos = c.v_lum_filter_pos[y];
            let mut val = 0;

            for z in 0..c.v_lum_filter_size {
                if src_pos + (z as i32) < c.src_h {
                    val += tmp[((src_pos + z as i32) as usize) * c.dst_w as usize + x] as u32
                        * c.v_lum_filter[y * c.v_lum_filter_size + z] as u32;
                }
            }

            dst[y * c.dst_w as usize + x] = ((val + (1 << (FILTER_BITS - 1))) >> FILTER_BITS) as u8;
        }
    }

    let mut difference: u32 = 0;
    for i in 0..c.dst_w as usize * c.dst_h as usize{
        difference += (dst[i] as i16 - target_image[i] as i16).abs() as u32;
    }

    print!("difference: {:?}", &difference);
    sp1_zkvm::io::commit(&difference);

    

    // print!("image data: {:?}", image);

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
