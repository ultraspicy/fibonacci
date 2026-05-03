global IMAGE_HEIGHT: u32 = 720;
global IMAGE_WIDTH: u32 = 1280;
global DELTA_BATCH_SIZE: u32 = 10;
global MAX_DELTA_LENGTH: u32 = 128 * 360; // 50% of pixels, divided by 10 for delta batch size.

// This only edits the video at a few deltas. We "batch" the deltas in groups of DELTA_BATCH_SIZE.
// This avoids some memory accesses at undetermined indices, which is one of the main costs.
//
// rT_delta_blur_s = r^T * (blur(current) - blur(prev)) * s, precomputed by the prover.
// The circuit proves this scalar equals r^T * A * (current - prev) * s via the sparse delta.
// No blurred-delta array is passed: blur spreads any pixel change across a ~3721-pixel
// neighborhood (radius=30), making the blurred delta always dense and unsuitable for sparse
// representation. Computing the scalar outside the circuit avoids this entirely.
fn main(delta_batches: [[Field; DELTA_BATCH_SIZE]; MAX_DELTA_LENGTH],
        delta_is: [Field; MAX_DELTA_LENGTH],
        delta_js: [[Field; DELTA_BATCH_SIZE]; MAX_DELTA_LENGTH],
        rT_delta_blur_s: pub Field,
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

    assert(rTAdeltaAs == rT_delta_blur_s, "Freivald's check failed");
}

// This triggers a 'bug' warning but I have mentioned why we're doing this.
unconstrained fn field_to_u32(val: Field) -> u32 {
    val as u32
}
