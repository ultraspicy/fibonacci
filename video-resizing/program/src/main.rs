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
use lib::blur_image;
use lib::freivalds_gblur::freivalds_verifier;
use lib::u8_to_u64_vec;
use lib::BlurContext;
sp1_zkvm::entrypoint!(main);
#[sp1_derive::cycle_tracker]

pub fn main() {
    println!("cycle-tracker-start: setup");
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    // let c = sp1_zkvm::io::read::<ResizeContext>();
    // let c = sp1_zkvm::io::read::<BlurContext>();
    // original image (in code u8 vector for RGB or YUV channel data) that
    // deserialized from each frame.
    let original_image: Vec<u8> = sp1_zkvm::io::read_vec();
    // ffmpeg output
    let target_image: Vec<u8> = sp1_zkvm::io::read_vec();

    println!("cycle-tracker-start: u64 pointer stuff");
    let freivalds_randomness_left_bytes = sp1_zkvm::io::read_vec();
    let freivalds_randomness_left = u8_to_u64_vec(freivalds_randomness_left_bytes);

    let freivalds_randomness_right_bytes = sp1_zkvm::io::read_vec();
    let freivalds_randomness_right = u8_to_u64_vec(freivalds_randomness_right_bytes);

    let r_left_t_b_bytes = sp1_zkvm::io::read_vec();
    let r_left_t_b: Vec<u64> = u8_to_u64_vec(r_left_t_b_bytes);

    let b_r_right_bytes = sp1_zkvm::io::read_vec();
    let b_r_right: Vec<u64> = u8_to_u64_vec(b_r_right_bytes);

    let channel_blurred_bytes = sp1_zkvm::io::read_vec();
    let channel_blurred: Vec<u64> = u8_to_u64_vec(channel_blurred_bytes);

    let image_height = sp1_zkvm::io::read::<usize>();
    let image_width = sp1_zkvm::io::read::<usize>();
    println!("cycle-tracker-end: u64 pointer stuff");

    // let mut tmp = vec![0u8; c.width as usize * c.height as usize];

    // // hard code here
    // const FILTER_BITS: i32 = 14;
    // //const FILTER_SCALE: i32 = 1 << FILTER_BITS;

    // Horizontal scaling + Vertical scaling is a over-simplified version of ffmpeg bilinear
    // Horizontal scaling
    println!("cycle-tracker-end: setup");

    println!("cycle-tracker-start: verifier");
    freivalds_verifier(
        freivalds_randomness_left,
        freivalds_randomness_right,
        r_left_t_b,
        b_r_right,
        &original_image,
        &channel_blurred,
        image_height,
        image_width,
    );
    println!("cycle-tracker-end: verifier");
    // println!("cycle-tracker-start: horizontal filter");
    // for y in 0..c.src_h as usize {
    //     for x in 0..c.dst_w as usize {
    //         let src_pos = c.filter_pos[x];
    //         let mut val = 0;

    //         for z in 0..c.filter_size {
    //             if src_pos + (z as i32) < c.src_w {
    //                 // create a var
    //                 // instead of +z, +1 each time
    //                 // print out the filter first and try to get rid of multiplication
    //                 // performance impli on u8/u32
    //                 // moving avg
    //                 // add RISC-V instruction to SP1 to speed up the z -loop
    //                 // Fiat-ch spot checking
    //                 val += original_image[y * c.src_w as usize + (src_pos as usize + z)] as u32
    //                     * c.filter[x * c.filter_size + z] as u32;
    //             }
    //         }

    //         tmp[y * c.dst_w as usize + x] = ((val + (1 << (FILTER_BITS - 1))) >> FILTER_BITS) as u8;
    //     }
    // }
    // println!("cycle-tracker-end: horizontal filter");
    // println!("cycle-tracker-start: vertical filter");
    // // Vertical scaling
    // for y in 0..c.dst_h as usize {
    //     for x in 0..c.dst_w as usize {
    //         let src_pos = c.v_lum_filter_pos[y];
    //         let mut val = 0;
    //         for z in 0..c.v_lum_filter_size {
    //             if src_pos + (z as i32) < c.src_h {
    //                 val += tmp[((src_pos + z as i32) as usize) * c.dst_w as usize + x] as u32
    //                     * c.v_lum_filter[y * c.v_lum_filter_size + z] as u32;
    //             }
    //         }

    //         dst[y * c.dst_w as usize + x] = ((val + (1 << (FILTER_BITS - 1))) >> FILTER_BITS) as u8;
    //     }
    // }
    // println!("cycle-tracker-end: vertical filter");

    println!("cycle-tracker-start: compute com");
    let mut dst: Vec<u8> = channel_blurred
        .into_iter()
        .map(|x| (x >> 48) as u8)
        .collect();
    //let mut difference: Vec<usize> = Vec::new();
    //let mut difference: usize = 0;
    let limit = 100;
    let mut within_limit = true;
    for i in 0..dst.len() {
        let difference = (dst[i] as isize - target_image[i] as isize).unsigned_abs();
        if difference >= limit {
            within_limit = false;
            sp1_zkvm::io::commit(&within_limit);
            return;
        }
        //difference.push((dst[i] as isize - target_image[i] as isize).unsigned_abs());
    }
    println!("cycle-tracker-end: compute com");

    //print!("difference: {:?}", &difference);
    println!("cycle-tracker-start: commit");
    sp1_zkvm::io::commit(&within_limit);
    println!("cycle-tracker-end: commit");
}
