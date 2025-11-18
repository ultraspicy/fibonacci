global IMAGE_HEIGHT: u32 = 240;
global IMAGE_WIDTH: u32 = 320;
global TARGET_HEIGHT: u32 = 180;
global TARGET_WIDTH: u32 = 240;

fn main(
    original_image: [[Field; IMAGE_WIDTH]; IMAGE_HEIGHT],
    resized_image: [[Field; TARGET_WIDTH]; TARGET_HEIGHT]
) -> pub Field {
    
    // Calculate scale factors (in fixed point)
    let scale_x = (IMAGE_WIDTH << 16) / TARGET_WIDTH;
    let scale_y = (IMAGE_HEIGHT << 16) / TARGET_HEIGHT;
    
    let mut computed_resized = [[0 as Field; TARGET_WIDTH]; TARGET_HEIGHT];
    
    // Nearest neighbor resize
    for i in 0..TARGET_HEIGHT {
        for j in 0..TARGET_WIDTH {
            // Map destination to source
            let src_y = ((i * scale_y) >> 16);
            let src_x = ((j * scale_x) >> 16);
            
            computed_resized[i][j] = original_image[src_y][src_x];
        }
    }
    
    // Verify
    let mut total_diff: Field = 0;
    for i in 0..TARGET_HEIGHT {
        for j in 0..TARGET_WIDTH {
            assert(
                computed_resized[i][j] == resized_image[i][j],
                "Resize verification failed"
            );
            let diff = computed_resized[i][j] - resized_image[i][j];
            total_diff += diff * diff;
        }
    }
    
    total_diff
}

#[test]
fn test_nearest_neighbor() {
    let original = [
        [100 as Field, 150 as Field, 200 as Field, 250 as Field],
        [110 as Field, 160 as Field, 210 as Field, 255 as Field]
    ];
    
    // 4x2 -> 2x1 resize
    let resized = [[100 as Field, 200 as Field]];
    
    main(original, resized);
}