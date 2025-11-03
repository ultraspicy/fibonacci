global IMAGE_HEIGHT: u32 = 720;
global IMAGE_WIDTH: u32 = 1280;
global MAX_DELTA_LENGTH: u32 = 128 * 720; // 10% of pixels

// Delta is a list of triples, where the first element is the change between an input and output pixel,
// while the second/third values are the indices of that pixel in the original image.
fn main(delta: [[Field; MAX_DELTA_LENGTH]; 3], transformed_delta: [[Field;MAX_DELTA_LENGTH]; 3], r: pub [Field; IMAGE_HEIGHT], s: pub [Field; IMAGE_WIDTH], rTA: pub [Field; IMAGE_HEIGHT], As: pub [Field; IMAGE_WIDTH]) {
    let mut deltaAs = [0; IMAGE_HEIGHT];
    for idx in 0..MAX_DELTA_LENGTH {
        let pixel_change = delta[0][idx];
        // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
        let pixel_i = unsafe { field_to_u32(delta[1][idx]) };
        // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
        let pixel_j = unsafe { field_to_u32(delta[2][idx]) };
        deltaAs[pixel_i] += pixel_change * As[pixel_j];
    }

    let mut rTAdeltaAs= 0;
    for i in 0..IMAGE_HEIGHT {
        rTAdeltaAs += rTA[i] * deltaAs[i];
    }

    let mut delta_fs = [0; IMAGE_HEIGHT];
    for idx in 0..MAX_DELTA_LENGTH {
        let pixel_change = transformed_delta[0][idx];
        // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
        let pixel_i = unsafe { field_to_u32(delta[1][idx]) };
        // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
        let pixel_j = unsafe { field_to_u32(delta[2][idx]) };
        delta_fs[pixel_i] += pixel_change * s[pixel_j];
    }

    let mut rTdelta_fs= 0;
    for i in 0..IMAGE_HEIGHT {
        rTdelta_fs += r[i] * delta_fs[i];
    }

    assert(rTAdeltaAs == rTdelta_fs, "Freivald's check failed");
}

// This triggers a 'bug' warning but I have mentioned why we're doing this.
unconstrained fn field_to_u32(val: Field) -> u32 {
    val as u32
}