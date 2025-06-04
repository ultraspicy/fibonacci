#![no_main]
use lib::ResizeContext;
sp1_zkvm::entrypoint!(main);
use blake3::hash;
#[sp1_derive::cycle_tracker]

pub fn main() {
    println!("cycle-tracker-start: setup");
    let c = sp1_zkvm::io::read::<ResizeContext>();
    let original_image: Vec<u8> = sp1_zkvm::io::read_vec();
    let target_image: Vec<u8> = sp1_zkvm::io::read_vec();

    // let middle_target_image: Vec<u32> = sp1_zkvm::io::read::<Vec<u32>>();
    // let r = sp1_zkvm::io::read::<Vec<u32>>();
    // let s = sp1_zkvm::io::read::<Vec<u32>>();

    // let freivalds_r = sp1_zkvm::io::read::<Vec<u32>>();
    // let freivalds_s = sp1_zkvm::io::read::<Vec<u32>>();
    let mut tmp = vec![0u8; c.dst_w as usize * c.src_h as usize];
    let mut dst = vec![0u8; c.dst_w as usize * c.dst_h as usize];
    // let mut tmp = vec![0u8; c.width as usize * c.height as usize];
    
    /*
    Prove 1: prove r @ original_image @ s = freivalds_r @ middle_target_image @ freivalds_s
    r = freivalds_r @ H
    s = V @ freivalds_s
    */

    const FILTER_BITS: i32 = 14;
    const FILTER_SCALE: i32 = 1 << FILTER_BITS;

    println!("cycle-tracker-start: horizontal filter");
    for y in 0..c.src_h as usize {
        for x in 0..c.dst_w as usize {
            let src_pos = c.filter_pos[x];
            let mut val = 0;

            for z in 0..c.filter_size {
                if src_pos + (z as i32) < c.src_w {
                    // create a var
                    // instead of +z, +1 each time
                    // print out the filter first and try to get rid of multiplication
                    // performance impli on u8/u32
                    // moving avg
                    // add RISC-V instruction to SP1 to speed up the z -loop
                    // Fiat-ch spot checking
                    val += original_image[y * c.src_w as usize + (src_pos as usize + z)] as u32
                        * c.filter[x * c.filter_size + z] as u32;
                }
            }

            tmp[y * c.dst_w as usize + x] = ((val + (1 << (FILTER_BITS - 1))) >> FILTER_BITS) as u8;
        }
    }
    println!("cycle-tracker-end: horizontal filter");
    println!("cycle-tracker-start: vertical filter");
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
    println!("cycle-tracker-end: vertical filter");

    // Calculate dst = r @ original_image @ s using matrix multiplication
    // original_image is a flattened matrix of size r_size * s_size
    // let r_size = r.len();
    // let s_size = s.len();

    // First multiply original_image (r_size x s_size) with s (s_size x 1)
    // let mut temp = vec![0u32; r_size];
    // for i in 0..r_size {
    //     for j in 0..s_size {
    //         temp[i] += (original_image[i * s_size + j] as u32) * s[j];
    //     }
    // }

    // Then multiply r (1 x r_size) with the result (r_size x 1)
    // let mut sum = 0u32;
    // for i in 0..r_size {
    //     sum += r[i] * temp[i];
    // }

    // let mut tmp_freivalds = vec![0u32; r_size];
    // let freivalds_s_size = freivalds_s.len();
    // let freivalds_r_size = freivalds_r.len();

    // for i in 0..freivalds_r_size {
    //     for j in 0..freivalds_s_size {
    //         tmp_freivalds[i] += (middle_target_image[i * freivalds_s_size + j] as u32) * freivalds_s[j];
    //     }
    // }

    // let mut sum_freivalds = 0u32;
    // for i in 0..freivalds_r_size {
    //     sum_freivalds += freivalds_r[i] * tmp_freivalds[i];
    // }
    // if sum != sum_freivalds {
    //     sp1_zkvm::io::commit(&false);
    //     return;
    // }
    // else {
    //     sp1_zkvm::io::commit(&true);
    // }
    
    /*
    Prove 2: prove |target_image - middle_target_image| <= 20
    */
    let limit1 = 20;
    let limit2 = 50;
    let mut cnt1 = 0;
    let mut cnt2 = 0;
    for i in 0..dst.len() {
        let middle_val = dst[i] as u32;
        let target_val = target_image[i] as u32;
        let difference = if middle_val > target_val {
            middle_val - target_val
        } else {
            target_val - middle_val
        };
        if difference > limit1 {
            cnt1 += 1;
        }
        if difference > limit2 {
            cnt2 += 1;
        }
    }
    sp1_zkvm::io::commit(&cnt1);
    sp1_zkvm::io::commit(&cnt2);
    let hash = blake3::hash(&target_image);
    sp1_zkvm::io::commit(&hash);
    //sp1_zkvm::io::commit(&hash(&target_image));
    //print!("difference: {:?}", &difference);
    println!("cycle-tracker-start: commit");
    println!("cycle-tracker-end: commit");
}
