global IMAGE_HEIGHT: u32 = 720;
global IMAGE_WIDTH: u32 = 1280;
// global BLUR_DIAMETER: u32 = 5;
global BLUR_RADIUS: u32 = 2; // Radius is floor of diameter / 2

fn main(original_image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT], edited_image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT], r: pub [Field; IMAGE_HEIGHT], s: pub [Field; IMAGE_WIDTH], rTA: pub [Field; IMAGE_HEIGHT], As: pub [Field; IMAGE_WIDTH]) -> pub [Field; 2] {
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
            sum += edited_image[i][j] * s[j];
        }
        Fs[i] = sum;
    }

    let mut rTFs= 0;
    for i in 0..IMAGE_HEIGHT {
        rTFs += r[i] * Fs[i];
    }

    assert(rTFs == rTAIAs, "Freivald's check failed");
    [rTFs, rTAIAs]

    // // Handle interior pixels (full 5x5 neighborhood)
    // for i in BLUR_RADIUS..IMAGE_HEIGHT - BLUR_RADIUS {
    //     for j in BLUR_RADIUS..IMAGE_WIDTH - BLUR_RADIUS {
    //         for ii in i - BLUR_RADIUS..i + BLUR_RADIUS + 1 {
    //             for jj in j - BLUR_RADIUS..j + BLUR_RADIUS + 1 {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle top-left corner
    // for i in 0..BLUR_RADIUS {
    //     for j in 0..BLUR_RADIUS {
    //         for ii in 0..i + BLUR_RADIUS + 1 {
    //             for jj in 0..j + BLUR_RADIUS + 1 {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle top edge (excluding corners)
    // for i in 0..BLUR_RADIUS {
    //     for j in BLUR_RADIUS..IMAGE_WIDTH - BLUR_RADIUS {
    //         for ii in 0..i + BLUR_RADIUS + 1 {
    //             for jj in j - BLUR_RADIUS..j + BLUR_RADIUS + 1 {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle top-right corner
    // for i in 0..BLUR_RADIUS {
    //     for j in IMAGE_WIDTH - BLUR_RADIUS..IMAGE_WIDTH {
    //         for ii in 0..i + BLUR_RADIUS + 1 {
    //             for jj in j - BLUR_RADIUS..IMAGE_WIDTH {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle bottom-left corner
    // for i in IMAGE_HEIGHT - BLUR_RADIUS..IMAGE_HEIGHT {
    //     for j in 0..BLUR_RADIUS {
    //         for ii in i - BLUR_RADIUS..IMAGE_HEIGHT {
    //             for jj in 0..j + BLUR_RADIUS + 1 {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle bottom edge (excluding corners)
    // for i in IMAGE_HEIGHT - BLUR_RADIUS..IMAGE_HEIGHT {
    //     for j in BLUR_RADIUS..IMAGE_WIDTH - BLUR_RADIUS {
    //         for ii in i - BLUR_RADIUS..IMAGE_HEIGHT {
    //             for jj in j - BLUR_RADIUS..j + BLUR_RADIUS + 1 {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle bottom-right corner
    // for i in IMAGE_HEIGHT - BLUR_RADIUS..IMAGE_HEIGHT {
    //     for j in IMAGE_WIDTH - BLUR_RADIUS..IMAGE_WIDTH {
    //         for ii in i - BLUR_RADIUS..IMAGE_HEIGHT {
    //             for jj in j - BLUR_RADIUS..IMAGE_WIDTH {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle left boundary columns (excluding corners already handled)
    // for i in BLUR_RADIUS..IMAGE_HEIGHT - BLUR_RADIUS {
    //     for j in 0..BLUR_RADIUS {
    //         for ii in i - BLUR_RADIUS..i + BLUR_RADIUS + 1 {
    //             for jj in 0..j + BLUR_RADIUS + 1 {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }
    
    // // Handle right boundary columns (excluding corners already handled)
    // for i in BLUR_RADIUS..IMAGE_HEIGHT - BLUR_RADIUS {
    //     for j in IMAGE_WIDTH - BLUR_RADIUS..IMAGE_WIDTH {
    //         for ii in i - BLUR_RADIUS..i + BLUR_RADIUS + 1 {
    //             for jj in j - BLUR_RADIUS..IMAGE_WIDTH {
    //                 output[i][j] = output[i][j] + original_image[ii][jj];
    //             }
    //         }
    //     }
    // }

    // output
}