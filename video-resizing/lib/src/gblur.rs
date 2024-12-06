use serde::{Deserialize, Serialize};
use std::cmp::{max, min};

// Adopted from:
// https://github.com/FFmpeg/FFmpeg/blob/d4966f0a7484afb71239690d3591cb4d18af4557/libavfilter/gblur.h
//

#[derive(Serialize, Deserialize, Debug)]
pub struct BlurContext {
    // Inputs
    pub sigma: f32,
    pub sigma_v: f32,
    pub steps: i32,

    // Implementation-level things, currently unused.
    pub flt: bool,
    pub depth: i32,

    // We limit to the case where width/height is the same for each color channel unlike ffmpeg.
    // All 3 are derived from the input image.
    pub width: usize,
    pub height: usize,
    pub stride: usize,

    // localBuf is not actually used
    // and we pass in the buffer of pixel values directly

    // Derived parameters for gblur
    pub boundaryscale: f32,
    pub boundaryscale_v: f32,
    pub postscale: f32,
    pub postscale_v: f32,
    pub nu: f32,
    pub nu_v: f32,
}

impl BlurContext {
    pub fn new(
        sigma: f32,
        sigma_v: f32,
        steps: i32,
        image_width: usize,
        image_height: usize,
    ) -> Option<Self> {
        let (boundaryscale, postscale, nu) = Self::set_params(sigma, steps);
        let (boundaryscale_v, postscale_v, nu_v) = Self::set_params(sigma_v, steps);
        let mut context = BlurContext {
            sigma,
            sigma_v,
            steps,
            flt: true, // Implementing the "float support" flavor
            depth: 8,  // Implementing the 8-bit color channels version
            width: image_width,
            height: image_height,
            stride: 0,
            boundaryscale,
            boundaryscale_v,
            postscale,
            postscale_v,
            nu,
            nu_v,
        };
        Some(context)
    }

    fn set_params(sigma: f32, steps: i32) -> (f32, f32, f32) {
        let f_steps = steps as f32;
        let lambda = ((sigma * sigma) / (2.0 * f_steps)) as f64;
        let dnu = ((1.0 + (2.0 * lambda) - (1.0 + (4.0 * lambda)).sqrt()) / (2.0 * lambda));
        let mut postscale = (dnu / lambda).powi(steps);
        let mut boundaryscale = 1.0f64 / (1.0f64 - dnu);
        let mut nu = dnu as f32;

        if !postscale.is_normal() {
            postscale = 1.0f64;
        }
        if !boundaryscale.is_normal() {
            boundaryscale = 1.0f64;
        }
        if !nu.is_normal() {
            nu = 0.0;
        }

        (postscale as f32, boundaryscale as f32, nu)
    }

    fn horiz_slice(c: &BlurContext, src: &mut [f32]) {
        let (height, width) = (c.height, c.width);
        for y in 0..height {
            for _step in 0..c.steps {
                let row_start = (width * y);
                src[row_start] *= c.boundaryscale;

                for x in 1..width {
                    src[row_start + x] += c.nu * src[row_start + x - 1]
                }
                src[row_start + width - 1] *= c.boundaryscale;

                for x in (1..width).rev() {
                    src[row_start + x - 1] += c.nu * src[row_start + x];
                }
            }
        }
    }

    fn verti_slice(c: &BlurContext, src: &mut [f32]) {
        let width = c.width;
        let numpixels = src.len();
        for x in 0..width {
            for _step in 0..c.steps {
                let column_start = x;
                src[column_start] *= c.boundaryscale_v;

                for i in (column_start..src.len()).step_by(width) {
                    src[i] += c.nu_v * src[i - width];
                }

                src[numpixels - width + column_start] *= c.boundaryscale_v;

                for i in ((column_start + width)..numpixels).step_by(width).rev() {
                    src[i - width] += c.nu_v * src[i]
                }
            }
        }
    }

    fn postscale(c: &BlurContext, src: &mut [f32], output: &mut [u8]) {
        let (min_f, max_f) = (255f32, 0f32); // Limiting to the case where we have 8 bit color channels
        let postscale_factor = c.postscale * c.postscale_v;

        for i in 0..src.len() {
            src[i] *= postscale_factor;
            output[i] = src[i].max(min_f).min(max_f).round() as u8;
        }
    }
}

pub fn blur_image(c: &BlurContext, src: &[u8], dst: &mut [u8]) {
    let numpixels = src.len();
    let mut temp = vec![0.0f32; numpixels];
    for i in 0..numpixels {
        temp[i] = src[i] as f32;
    }
    BlurContext::horiz_slice(c, &mut temp);
    BlurContext::verti_slice(c, &mut temp);
    BlurContext::postscale(c, &mut temp, dst);
}