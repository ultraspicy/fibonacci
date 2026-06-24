"""
Verify that frame0_our_blur.png matches the Rust gblur logic.

Rust logic:
  kernel = exp(-0.5/sigma^2 * i^2) for i in [-30..30], normalized, floored to fixed-point (x * 2^32)
  blur matrix uses edge-clamp padding (equivalent to scipy mode='nearest')
  blurred = V @ image @ H (separable, no intermediate division)

ffmpeg is the base line we try to approximate, via command 
ffmpeg -y -i frame0_original.png -vf "gblur=sigma=10:steps=1" frame0_ffmpeg_blur_lossless.png  

We use scipy.ndimage.convolve1d with mode='nearest', which is equivalent to the
edge-clamp padding in the Rust create_gblur_matrix.
"""
import cv2
import numpy as np
from scipy.ndimage import convolve1d

SIGMA = 10.0
RADIUS = 30
KERNEL_SCALE = 1 << 32


def gaussian_kernel1d_float(sigma, radius):
    indices = np.arange(-radius, radius + 1, dtype=np.float64)
    phi = np.exp(-0.5 / (sigma ** 2) * indices ** 2)
    phi /= phi.sum()
    return phi


def gaussian_kernel1d_fixed(sigma, radius):
    """Exact Rust replica: floor(normalized_weight * 2^32), then normalize sum=1 for convolution."""
    phi = gaussian_kernel1d_float(sigma, radius)
    fixed = np.floor(phi * KERNEL_SCALE)
    return fixed / fixed.sum()  # renormalize so pixel values stay in 0-255


def blur_channel(channel, kernel):
    img = channel.astype(np.float64)
    # axis=0 = vertical (rows), axis=1 = horizontal (columns)
    tmp = convolve1d(img, kernel, axis=0, mode='nearest')
    return np.clip(np.round(convolve1d(tmp, kernel, axis=1, mode='nearest')), 0, 255).astype(np.uint8)


def compare(label, result_bgr, reference):
    diff = np.abs(result_bgr.astype(np.int32) - reference.astype(np.int32))
    n_pix = reference.shape[0] * reference.shape[1]
    print(f"\n{label}:")
    print(f"  max={diff.max()}  mean={diff.mean():.5f}  "
          f"px>0={(diff>0).any(axis=2).sum()}/{n_pix}  "
          f"px>1={(diff>1).any(axis=2).sum()}/{n_pix}")


def main():
    orig     = cv2.imread("frame0_original.png")
    our      = cv2.imread("frame0_our_blur.png")
    lossless = cv2.imread("frame0_ffmpeg_blur_lossless.png")
    assert orig is not None, "Missing frame0_original.png"
    assert our  is not None, "Missing frame0_our_blur.png"

    rgb = cv2.cvtColor(orig, cv2.COLOR_BGR2RGB)

    # Variant A: fixed-point kernel (floored weights, renormalized) — exact Rust rounding
    k_fixed = gaussian_kernel1d_fixed(SIGMA, RADIUS)
    channels_a = [blur_channel(rgb[:,:,c], k_fixed) for c in range(3)]
    result_a = cv2.cvtColor(np.stack(channels_a, axis=2), cv2.COLOR_RGB2BGR)
    compare("Python fixed-point  vs frame0_our_blur", result_a, our)
    if lossless is not None:
        compare("Python fixed-point  vs ffmpeg_lossless",  result_a, lossless)

    # Variant B: float kernel (no fixed-point flooring)
    k_float = gaussian_kernel1d_float(SIGMA, RADIUS)
    channels_b = [blur_channel(rgb[:,:,c], k_float) for c in range(3)]
    result_b = cv2.cvtColor(np.stack(channels_b, axis=2), cv2.COLOR_RGB2BGR)
    compare("Python float-kernel  vs frame0_our_blur", result_b, our)
    if lossless is not None:
        compare("Python float-kernel  vs ffmpeg_lossless",  result_b, lossless)

    # Also cross-check our_blur vs lossless directly
    if lossless is not None:
        compare("frame0_our_blur      vs ffmpeg_lossless",  our, lossless)


if __name__ == "__main__":
    main()
