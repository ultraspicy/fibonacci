use serde::{Deserialize, Serialize};

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

// demo image processing
// pub fn demo_processing(image: &[u8]) -> Vec<u8> {
//     image.iter().map(|&x| x.wrapping_add(1)).collect()
// }

// pub fn print_data_sample(data: &[u8], sample_size: usize) {
//     println!("Data sample (first {} values):", sample_size);
//     for (i, &value) in data.iter().take(sample_size).enumerate() {
//         print!("{:3} ", value);
//         if (i + 1) % 16 == 0 {
//             println!();
//         }
//     }
//     println!();
// }

// pub fn print_image_summary(width: usize, height: usize, data: &[u8]) {
//     let mut sum: u64 = 0;
//     let mut min_val: u8 = 255;
//     let mut max_val: u8 = 0;

//     for &pixel in data.iter() {
//         sum += pixel as u64;
//         min_val = min(min_val, pixel);
//         max_val = max(max_val, pixel);
//     }

//     let avg = sum as f64 / (width * height) as f64;

//     println!("Image Summary ({}x{}):", width, height);
//     println!("Min value: {}", min_val);
//     println!("Max value: {}", max_val);
//     println!("Average value: {:.2}", avg);
// }

const FILTER_BITS: i32 = 14;
const FILTER_SCALE: i32 = 1 << FILTER_BITS;

#[derive(Serialize, Deserialize, Debug)]
pub struct ResizeContext {
    pub filter_pos: Vec<i32>,
    pub filter: Vec<i16>,
    pub filter_size: usize,
    pub v_lum_filter_pos: Vec<i32>,
    pub v_lum_filter: Vec<i16>,
    pub v_lum_filter_size: usize,
    pub dst_w: i32,
    pub dst_h: i32,
    pub src_w: i32,
    pub src_h: i32,
}

impl ResizeContext {
    pub fn new(src_w: i32, src_h: i32, dst_w: i32, dst_h: i32) -> Option<Self> {
        let filter_size = 2; //should be 4
        let mut context = ResizeContext {
            filter_pos: Vec::new(),
            filter: Vec::new(),
            filter_size,
            v_lum_filter_pos: Vec::new(),
            v_lum_filter: Vec::new(),
            v_lum_filter_size: filter_size,
            dst_w,
            dst_h,
            src_w,
            src_h,
        };

        if context.init_filter(src_w, dst_w, filter_size).is_err() {
            return None;
        }

        context.init_vfilter(src_h, dst_h, filter_size);
        Some(context)
    }

    // horizontal filter setup
    fn init_filter(&mut self, src_w: i32, dst_w: i32, _filter_size: usize) -> Result<(), ()> {
        // Nov 20, 2024: bug, the impl can only support fitler size of 2
        let filter_size_corrected = 2;
        // notes for precompile
        //  - +1 so that it rounds towards the nearest integer instead of always rounding down
        //  - the core is src_w/dst_w, right/left shift is just a fixed-point representation
        //  - x_inc is a pixel ratio from src to dst
        let x_inc: i64 = (((src_w as i64) << 16) / dst_w as i64 + 1) >> 1;

        self.filter_pos = vec![0; dst_w as usize];
        self.filter = vec![0; dst_w as usize * filter_size_corrected];

        for i in 0..dst_w as usize {
            // get the starting position of src image, it doesn't to be an integer since we are
            // using fixed-point. We multiply a big number so the fractional is also scaled up
            // propotionally with i
            let src_pos: i64 = (i as i64 * x_inc) >> 15;
            // normalize the fractional to FILTER_BITS
            // so the left weight an right weight will sum to 1
            let xx_inc = x_inc & 0xffff;
            let xx = (xx_inc * (1 << FILTER_BITS) / x_inc) as i32;

            self.filter_pos[i] = src_pos as i32;
            // structure of filter weigjt
            // [pixel1_weight1, pixel1_weight2, pixel2_weight1, pixel2_weight1 ...]
            for j in 0..filter_size_corrected {
                let coeff = if j == 0 { (1 << FILTER_BITS) - xx } else { xx };
                self.filter[i * filter_size_corrected + j] = coeff as i16;
            }

            // minor adjustment if the two weight doesn't add up to 1 (FILTER_SCALE)
            // comment out for simplify precompile
            // let mut sum = 0;
            // for j in 0..filter_size_corrected {
            //     sum += self.filter[i * filter_size_corrected + j] as i64;
            // }

            // if sum != FILTER_SCALE as i64 {
            //     for j in 0..filter_size_corrected {
            //         let coeff = (self.filter[i * filter_size_corrected + j] as i64 * FILTER_SCALE as i64) / sum;
            //         self.filter[i * filter_size_corrected + j] = coeff as i16;
            //     }
            // }
        }

        Ok(())
    }

    fn init_vfilter(&mut self, src_h: i32, dst_h: i32, filter_size: usize) {
        self.v_lum_filter_pos = vec![0; dst_h as usize];
        self.v_lum_filter = vec![0; dst_h as usize * filter_size];

        let scale = src_h as f64 / dst_h as f64;

        for i in 0..dst_h as usize {
            let center = (i as f64 + 0.5) * scale - 0.5;
            let top = (center - filter_size as f64 / 2.0).ceil() as i32;

            self.v_lum_filter_pos[i] = top;

            for j in 0..filter_size {
                let weight = if filter_size > 1 {
                    1.0 - ((j as f64 - (center - top as f64)).abs() / (filter_size as f64 / 2.0))
                } else {
                    1.0
                };
                self.v_lum_filter[i * filter_size + j] = (weight * FILTER_SCALE as f64) as i16;
            }

            let sum: i32 = self.v_lum_filter[i * filter_size..(i + 1) * filter_size]
                .iter()
                .map(|&val| val as i32)
                .sum();

            for j in 0..filter_size {
                self.v_lum_filter[i * filter_size + j] =
                    (self.v_lum_filter[i * filter_size + j] as i32 * FILTER_SCALE / sum) as i16;
            }
        }
    }
}

pub fn load_image_from_file(input_file: &str) -> Vec<u8> {
    let mut image: Vec<u8> = Vec::new();

    let input_path = Path::new(input_file);
    let file = File::open(&input_path).expect("Failed to open input file");
    let reader = BufReader::new(file);

    for (i, line) in reader.lines().enumerate() {
        match line {
            Ok(line_data) => {
                // Split the line into separate numbers
                for value_str in line_data.split_whitespace() {
                    match value_str.parse::<u8>() {
                        Ok(value) => {
                            image.push(value);
                        }
                        Err(_) => {
                            println!("Error parsing value on line {}: '{}'", i + 1, value_str);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error reading line {}: {:?}", i + 1, e);
            }
        }
    }

    image
}

pub fn scale_image(
    c: &ResizeContext,
    src: &[u8],
    src_stride: i32,
    dst: &mut [u8],
    dst_stride: i32,
) {
    let mut tmp = vec![0u8; c.dst_w as usize * c.src_h as usize];

    // Horizontal scaling
    for y in 0..c.src_h as usize {
        for x in 0..c.dst_w as usize {
            let src_pos = c.filter_pos[x];
            let mut val = 0;

            for z in 0..c.filter_size {
                if src_pos + (z as i32) < c.src_w {
                    val += src[y * src_stride as usize + (src_pos as usize + z)] as u32
                        * c.filter[x * c.filter_size + z] as u32;
                }
            }

            tmp[y * c.dst_w as usize + x] = ((val + (1 << (FILTER_BITS - 1))) >> FILTER_BITS) as u8;
        }
    }

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

            dst[y * dst_stride as usize + x] =
                ((val + (1 << (FILTER_BITS - 1))) >> FILTER_BITS) as u8;
        }
    }
}
