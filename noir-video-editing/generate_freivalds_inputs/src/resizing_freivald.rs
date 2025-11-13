use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};

const FILTER_BITS: u32 = 11;
const FILTER_SCALE: u64 = 1u64 << FILTER_BITS;

pub fn generate_horizontal_filter(src_w: usize, dst_w: usize) -> (Vec<usize>, Vec<Fr>) {
    let filter_size = 4;
    let mut filter_pos = Vec::with_capacity(dst_w);
    let mut filter_coeffs = Vec::with_capacity(dst_w * filter_size);
    
    // x_inc is scaling factor in 16.16 fixed point
    let x_inc = ((src_w << 16) / dst_w + 1) >> 1;
    
    for i in 0..dst_w {
        // Get source position in 16.16 fixed point
        let src_pos = (i * x_inc) >> 15;
        
        // Get fractional part normalized to FILTER_BITS
        let xx_inc = x_inc & 0xffff;
        let xx = (xx_inc * (1 << FILTER_BITS)) / x_inc;
        
        filter_pos.push(src_pos);
        
        // Calculate filter weights
        for j in 0..filter_size {
            let coeff_u64 = if j == 0 {
                (1u64 << FILTER_BITS) - (xx as u64)
            } else {
                xx as u64
            };
            filter_coeffs.push(Fr::from(coeff_u64));
        }
    }

    (filter_pos, filter_coeffs)
}

pub fn generate_vertical_filter(src_h: usize, dst_h: usize, filter_size: usize) -> (Vec<i32>, Vec<Fr>) {
    let mut filter_pos = Vec::with_capacity(dst_h);
    let mut filter_coeffs = Vec::with_capacity(dst_h * filter_size);
    let scale = src_h as f64 / dst_h as f64;
    
    for i in 0..dst_h {
        let center = (i as f64 + 0.5) * scale - 0.5;
        let top = (center - filter_size as f64 / 2.0).ceil() as i32;
        filter_pos.push(top);
        
        let mut weights = Vec::with_capacity(filter_size);
        for j in 0..filter_size {
            let weight = if filter_size > 1 {
                1.0 - (((j as f64) - (center - top as f64)).abs() / (filter_size as f64 / 2.0))
            } else {
                1.0
            };
            weights.push((weight * FILTER_SCALE as f64) as u64);
        }
        
        // Normalize weights
        let total: u64 = weights.iter().sum();
        let normalized_weights: Vec<Fr> = weights
            .iter()
            .map(|&w| Fr::from(w * FILTER_SCALE / total))
            .collect();
        filter_coeffs.extend(normalized_weights);
    }
    
    (filter_pos, filter_coeffs)
}

pub fn build_horizontal_matrix(src_w: usize, dst_w: usize) -> Vec<Vec<Fr>> {
    let (h_pos, h_coeffs) = generate_horizontal_filter(src_w, dst_w);
    let filter_size = 4;
    
    // Create matrix for horizontal scaling
    let mut h = vec![vec![Fr::zero(); dst_w]; src_w];
    
    // Fill in the matrix based on filter positions and coefficients
    for x in 0..dst_w {
        let src_pos = h_pos[x];
        for z in 0..filter_size {
            if src_pos + z < src_w {
                h[src_pos + z][x] = h_coeffs[x * filter_size + z];
            }
        }
    }
    h
}

pub fn build_vertical_matrix(src_h: usize, dst_h: usize) -> Vec<Vec<Fr>> {
    let (v_pos, v_coeffs) = generate_vertical_filter(src_h, dst_h, 4);
    let filter_size = 4;
    
    // Create matrix for vertical scaling
    let mut v = vec![vec![Fr::zero(); src_h]; dst_h];
    
    // Fill in the matrix based on filter positions and coefficients
    for y in 0..dst_h {
        let src_pos = v_pos[y];
        for z in 0..filter_size {
            if src_pos + z < src_h as i32 && src_pos + z >= 0 {
                v[y][(src_pos + z) as usize] = v_coeffs[y * filter_size + z];
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_generation() {
        let src_w = 270;
        let src_h = 480;
        let dst_w = 135;
        let dst_h = 240;

        let (h_pos, h_coeffs) = generate_horizontal_filter(src_w, dst_h);
        let (v_pos, v_coeffs) = generate_vertical_filter(src_h, dst_h, 4);

        assert!(!h_pos.is_empty());
        assert!(!h_coeffs.is_empty());
        assert!(!v_pos.is_empty());
        assert!(!v_coeffs.is_empty());
    }
}