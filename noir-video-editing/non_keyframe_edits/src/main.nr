global IMAGE_HEIGHT: u32 = 720;
global IMAGE_WIDTH: u32 = 1280;
global DELTA_BATCH_SIZE: u32 = 10;
global MAX_DELTA_LENGTH: u32 = 128 * 72; // 10% of pixels, further divided by 10 because of the delta batch size.

// This only edits the video at a few deltas. We "batch" the deltas in groups of DELTA_BATCH_SIZE.
// This avoids some memory accesses at undetermined indices, which is one of the main costs.
fn main(delta_batches: [[Field; DELTA_BATCH_SIZE]; MAX_DELTA_LENGTH], 
        delta_is: [Field; MAX_DELTA_LENGTH], 
        delta_js: [[Field; DELTA_BATCH_SIZE]; MAX_DELTA_LENGTH],
        transformed_delta_batches: [[Field; DELTA_BATCH_SIZE]; MAX_DELTA_LENGTH],
        transformed_delta_is: [Field; MAX_DELTA_LENGTH],
        transformed_delta_js: [[Field; DELTA_BATCH_SIZE]; MAX_DELTA_LENGTH], 
        r: pub [Field; IMAGE_HEIGHT], 
        s: pub [Field; IMAGE_WIDTH], 
        rTA: pub [Field; IMAGE_HEIGHT], 
        As: pub [Field; IMAGE_WIDTH]) {
    let mut deltaAs = [0; IMAGE_HEIGHT];
    for batch_idx in 0..MAX_DELTA_LENGTH {
        // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
        let pixel_i = unsafe { field_to_u32(delta_is[batch_idx]) };
        let mut sum_to_add = 0;
        for idx_in_batch in 0..DELTA_BATCH_SIZE {
            let pixel_change = delta_batches[batch_idx][idx_in_batch];
            // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
            let pixel_j = unsafe { field_to_u32(delta_js[batch_idx][idx_in_batch]) };
            sum_to_add += pixel_change * As[pixel_j];
        }
        deltaAs[pixel_i] += sum_to_add;
    }

    let mut rTAdeltaAs= 0;
    for i in 0..IMAGE_HEIGHT {
        rTAdeltaAs += rTA[i] * deltaAs[i];
    }

    let mut delta_fs = [0; IMAGE_HEIGHT];
    for batch_idx in 0..MAX_DELTA_LENGTH {
        // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
        let pixel_i = unsafe { field_to_u32(transformed_delta_is[batch_idx]) };
        let mut sum_to_add = 0;
        for idx_in_batch in 0..DELTA_BATCH_SIZE {
            let pixel_change = transformed_delta_batches[batch_idx][idx_in_batch];
            // Safety: using unsafe block for demonstration purposes: Noir doesn't support this type of cast though it should be free.
            let pixel_j = unsafe { field_to_u32(transformed_delta_js[batch_idx][idx_in_batch]) };
            sum_to_add += pixel_change * s[pixel_j];
        }
        delta_fs[pixel_i] += sum_to_add;
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