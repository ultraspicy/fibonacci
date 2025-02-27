#![no_main]
sp1_zkvm::entrypoint!(main);
use blake3::hash;
use lib::u8_to_u32_vec;
#[sp1_derive::cycle_tracker]

pub fn main() {
    println!("cycle-tracker-start: setup");
    let original_image: Vec<u8> = sp1_zkvm::io::read_vec();
    let target_image: Vec<u8> = sp1_zkvm::io::read_vec();
    
    let middle_target_image_bytes = sp1_zkvm::io::read_vec();
    let middle_target_image = u8_to_u32_vec(middle_target_image_bytes);
    
    let r_bytes = sp1_zkvm::io::read_vec();
    let r = u8_to_u32_vec(r_bytes);
    
    let s_bytes = sp1_zkvm::io::read_vec();
    let s = u8_to_u32_vec(s_bytes);
    
    let freivalds_r_bytes = sp1_zkvm::io::read_vec();
    let freivalds_r = u8_to_u32_vec(freivalds_r_bytes);
    
    let freivalds_s_bytes = sp1_zkvm::io::read_vec();
    let freivalds_s = u8_to_u32_vec(freivalds_s_bytes);
    

    // let mut tmp = vec![0u8; c.width as usize * c.height as usize];
    
    /*
    Prove 1: prove r @ original_image @ s = freivalds_r @ middle_target_image @ freivalds_s
    r = freivalds_r @ H
    s = V @ freivalds_s
    */

    // Calculate dst = r @ original_image @ s using matrix multiplication
    // original_image is a flattened matrix of size r_size * s_size
    let r_size = r.len();
    let s_size = s.len();

    // First multiply original_image (r_size x s_size) with s (s_size x 1)
    let mut temp = vec![0u32; r_size];
    for i in 0..r_size {
        for j in 0..s_size {
            temp[i] += (original_image[i * s_size + j] as u32) * s[j];
        }
    }

    // Then multiply r (1 x r_size) with the result (r_size x 1)
    let mut sum = 0u32;
    for i in 0..r_size {
        sum += r[i] * temp[i];
    }

    let mut tmp_freivalds = vec![0u32; r_size];
    let freivalds_s_size = freivalds_s.len();
    let freivalds_r_size = freivalds_r.len();

    for i in 0..freivalds_r_size {
        for j in 0..freivalds_s_size {
            tmp_freivalds[i] += (middle_target_image[i * freivalds_s_size + j] as u32) * freivalds_s[j];
        }
    }

    let mut sum_freivalds = 0u32;
    for i in 0..freivalds_r_size {
        sum_freivalds += freivalds_r[i] * tmp_freivalds[i];
    }
    if sum != sum_freivalds {
        sp1_zkvm::io::commit(&false);
        return;
    }
    else {
        sp1_zkvm::io::commit(&true);
    }
    
    /*
    Prove 2: prove |target_image - middle_target_image| <= 20
    */
    let limit1 = 20;
    let limit2 = 50;
    let mut cnt1 = 0;
    let mut cnt2 = 0;
    for i in 0..middle_target_image.len() {
        let middle_val = middle_target_image[i]/(1<<22) as u32;
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

    // let hash = blake3::hash(&target_image);
    // sp1_zkvm::io::commit(&hash);
    //sp1_zkvm::io::commit(&hash(&target_image));
    //print!("difference: {:?}", &difference);
    println!("cycle-tracker-end: commit");
}
