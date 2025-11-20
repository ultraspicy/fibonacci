global IMAGE_HEIGHT: u32 = 400;
global IMAGE_WIDTH: u32 = 400;
global KERNEL_LEN: u32 = 3;
global KERNEL_RADIUS: u32 = 1; // Radius is floor of KERNEL_LEN / 2
// Make kernel have some stuff of representative bitlengths.
global KERNEL: [Field; KERNEL_LEN] = [65500, 765536, 
                                    //   65537, 65538, 
                                    //   65539, 65534, 
                                      8965533];

// fn bounds(idx: u32, limit: u32) -> (u32, u32) {
//     let start = if idx < KERNEL_RADIUS { 0 } else { idx - KERNEL_RADIUS };
//     let end = if idx + KERNEL_RADIUS >= limit { limit - 1 } else { idx + KERNEL_RADIUS };
//     (start, end)
// }

// // Convolve horizontally with a separable 1-D kernel.
// fn horizontal_pass(image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT]) -> [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT] {
//     let mut out = [[0; IMAGE_WIDTH]; IMAGE_HEIGHT];
//     for i in 0..IMAGE_HEIGHT {
//         for j in 0..IMAGE_WIDTH {
//             let (start_j, end_j) = bounds(j, IMAGE_WIDTH);
//             let mut acc = 0;
//             for jj in start_j..end_j + 1 {
//                 let k_idx = KERNEL_RADIUS + jj - j;
//                 acc = acc + image[i][jj] * KERNEL[k_idx];
//             }
//             out[i][j] = acc;
//         }
//     }
//     out
// }

// // Convolve vertically using the same separable 1-D kernel.
// fn vertical_pass(image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT]) -> [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT] {
//     let mut out = [[0; IMAGE_WIDTH]; IMAGE_HEIGHT];
//     for i in 0..IMAGE_HEIGHT {
//         let (start_i, end_i) = bounds(i, IMAGE_HEIGHT);
//         for j in 0..IMAGE_WIDTH {
//             let mut acc = 0;
//             for ii in start_i..end_i + 1 {
//                 let k_idx = KERNEL_RADIUS + ii - i;
//                 acc = acc + image[ii][j] * KERNEL[k_idx];
//             }
//             out[i][j] = acc;
//         }
//     }
//     out
// }

// // Two-pass separable convolution with an arbitrary 7-element kernel.
// fn main(original_image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT]) -> pub [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT] {
//     let horiz = horizontal_pass(original_image);
//     vertical_pass(horiz)
// }

fn main(original_image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT], 
        target_middle_image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT],
        r: pub [Field; IMAGE_HEIGHT], 
        s: pub [Field; IMAGE_WIDTH],
        rTA: pub [Field; IMAGE_HEIGHT],
        As: pub [Field; IMAGE_WIDTH]) -> pub ([Field; IMAGE_HEIGHT], [Field; IMAGE_WIDTH]) 
    {
    // // the edited image and output of Freivald's should be close to other pixel wise
    // for i in 0..IMAGE_HEIGHT {
    //     for j in 0..IMAGE_WIDTH {
    //         let pixel_diff_felt = (target_middle_image[i][j] - edited_image[i][j]) + PIXEL_THRESHOLD_FELT;
    //         // Safety: The range check on the next line constrains this, as before a result of not having an analog of reinterpret_cast.
    //          let pixel_diff = unsafe { field_to_u32(pixel_diff_felt) };
    //          // Can comment this out for benchmarking? Not theoretically needed constraint but it makes compiler happy.
    //         assert((pixel_diff as Field) == pixel_diff_felt);
    //         assert(pixel_diff < PIXEL_THRESHOLD_DOUBLE);
    //         pixel_diff_felt.assert_max_bit_size::<7>();
    //     }
    // }

    // after Freivald transformation, the left hand side should
    // be equal to the right hand side 
    let mut IAs = [0; IMAGE_HEIGHT];
    for i in 0..IMAGE_HEIGHT {
        let mut sum = 0;
        for j in 0..IMAGE_WIDTH {
            sum += original_image[i][j] * As[j];
        }
        IAs[i] = sum;
    }

    let mut rTAIAs= 0;
    for i in 0..IMAGE_HEIGHT {
        rTAIAs += rTA[i] * IAs[i];
    }

    let mut Fs = [0; IMAGE_HEIGHT];
    for i in 0..IMAGE_HEIGHT {
        let mut sum = 0;
        for j in 0..IMAGE_WIDTH {
            sum += target_middle_image[i][j] * s[j];
        }
        Fs[i] = sum;
    }

    let mut rTFs= 0;
    for i in 0..IMAGE_HEIGHT {
        rTFs += r[i] * Fs[i];
    }

    assert(rTFs == rTAIAs, "Freivald's check failed");
    (rTA, As)
}