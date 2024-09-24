//! Original goal: we want to prove the resulting video is the output of original video using ffmpeg
//!
//! This is difficult since ffmpeg has system-specifc implementation, so not every algos are always
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

use lib::Context;
pub fn main() {
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let c = sp1_zkvm::io::read::<Context>();
    // original image (in code u8 vector for RGB or YUV channel data) that deserialized from each 
    // frame.
    let original_image: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    // ffmpeg resized image, we try
    let target_image: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();

    let mut tmp = vec![0u8; c.dst_w as usize * c.src_h as usize];
    let mut dst = vec![0u8; c.dst_w as usize * c.dst_h as usize];

    // hard code here
    const FILTER_BITS: i32 = 14;
    //const FILTER_SCALE: i32 = 1 << FILTER_BITS;

    // Horizontal scaling
    for y in 0..c.src_h as usize {
        for x in 0..c.dst_w as usize {
            let src_pos = c.filter_pos[x];
            let mut val = 0;

            for z in 0..c.filter_size {
                if src_pos + (z as i32) < c.src_w {
                    val += original_image[y * c.src_w as usize + (src_pos as usize + z)] as u32
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

    //let mut difference: Vec<usize> = Vec::new();
    let mut difference: usize = 0;
    for i in 0..c.dst_w as usize * c.dst_h as usize{
        difference += (dst[i] as isize - target_image[i] as isize).unsigned_abs();
        //difference.push((dst[i] as isize - target_image[i] as isize).unsigned_abs());
    }

    //print!("difference: {:?}", &difference);
    sp1_zkvm::io::commit(&difference);
}
