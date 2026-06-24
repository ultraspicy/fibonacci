"""
Reverse-engineer the linear filter that ffmpeg's gblur applies, then re-apply
it and measure how far the result is from ffmpeg's own output.

Method: measure ffmpeg's impulse response (point-spread function).
  Feed a single bright pixel through `gblur` and read the blurred result -- that
  IS the convolution kernel ffmpeg applies. We use a 16-bit impulse so the
  kernel tails survive quantization (an 8-bit impulse has peak < 1 and rounds to
  zero). The recovered kernel is a plain linear FIR filter: the thing you'd make
  public and implement in-circuit.

Why it can't match perfectly: ffmpeg gblur is an IIR approximation with its own
boundary handling, so a finite FIR kernel with edge-clamp differs slightly --
mostly near the image borders. That residual is what we report.
"""
import cv2
import numpy as np
import subprocess

ORIG_PATH = "frame0_original.png"
BLUR_PATH = "frame0_ffmpeg_blur_lossless.png"
SIGMA = 10          # matches how frame0_ffmpeg_blur_lossless.png was generated
STEPS = 1
IMPULSE_SIZE = 257  # must comfortably exceed the kernel support
RADIUS = 80         # kernel radius; large enough to capture the Gaussian tails


def reverse_ffmpeg_gblur_filter(sigma=SIGMA, steps=STEPS, radius=RADIUS):
    """
    Recover ffmpeg's linear kernel via its impulse response, measured in FLOAT32
    (raw video) so the kernel is exact -- a 16-bit/8-bit impulse quantizes the
    tails and visibly degrades the match. Returns (kernel, shape).
    """
    size, c = IMPULSE_SIZE, IMPULSE_SIZE // 2
    imp = np.zeros((size, size), np.float32)
    imp[c, c] = 1.0
    imp.tofile("/tmp/_imp.raw")
    subprocess.run(
        ["ffmpeg", "-y", "-f", "rawvideo", "-pix_fmt", "grayf32le",
         "-s", f"{size}x{size}", "-i", "/tmp/_imp.raw",
         "-vf", f"gblur=sigma={sigma}:steps={steps}",
         "-f", "rawvideo", "-pix_fmt", "grayf32le", "/tmp/_imp_blur.raw"],
        capture_output=True, check=True)
    psf = np.fromfile("/tmp/_imp_blur.raw", dtype=np.float32).reshape(size, size).astype(np.float64)

    kernel = psf[c - radius:c + radius + 1, c - radius:c + radius + 1].copy()
    kernel /= kernel.sum()          # normalize DC gain to exactly 1
    return kernel, kernel.shape


def apply_filter(channel, kernel):
    out = cv2.filter2D(channel.astype(np.float64), -1, kernel,
                       borderType=cv2.BORDER_REPLICATE)   # edge-clamp padding
    return np.clip(np.round(out), 0, 255).astype(np.uint8)


def compare(name, a, b):
    diff = np.abs(a.astype(np.int32) - b.astype(np.int32))
    n = a.size
    mse = (diff.astype(np.float64) ** 2).mean()
    psnr = float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)
    print(f"  {name}: max={diff.max()} mean={diff.mean():.4f} "
          f"px>0={(diff>0).sum()}/{n} px>1={(diff>1).sum()} px>2={(diff>2).sum()} "
          f"PSNR={psnr:.2f}dB")


def main():
    orig = cv2.imread(ORIG_PATH)
    blur = cv2.imread(BLUR_PATH)
    assert orig is not None, f"missing {ORIG_PATH}"
    assert blur is not None, f"missing {BLUR_PATH}"
    assert orig.shape == blur.shape, f"shape mismatch {orig.shape} vs {blur.shape}"

    # 1. Recover the linear filter (ffmpeg gblur is channel-independent, so one
    #    kernel covers R, G and B -- we apply the same kernel to each channel).
    kernel, size = reverse_ffmpeg_gblur_filter()
    print("=== Recovered linear filter (ffmpeg gblur impulse response) ===")
    print(f"  size = {size[0]} x {size[1]}   (radius {size[0]//2})")
    print(f"  sum={kernel.sum():.6f}  peak={kernel.max():.6f}  min={kernel.min():.6f}")
    np.save("ffmpeg_gblur_kernel.npy", kernel)
    print("  saved kernel -> ffmpeg_gblur_kernel.npy")

    # 2. Re-blur the original with the recovered filter, per channel.
    recomputed = np.zeros_like(blur)
    for ch in range(3):
        recomputed[:, :, ch] = apply_filter(orig[:, :, ch], kernel)

    # 3. Compare against ffmpeg's own output.
    names = ["B", "G", "R"]   # cv2 channel order
    print("\n=== Recovered-filter output vs ffmpeg, per channel ===")
    for ch in range(3):
        compare(f"channel {names[ch]}", recomputed[:, :, ch], blur[:, :, ch])

    print("\n=== Whole image ===")
    diff = np.abs(recomputed.astype(np.int32) - blur.astype(np.int32))
    npix = orig.shape[0] * orig.shape[1]
    print(f"  pixels differing in any channel: {(diff>0).any(axis=2).sum()}/{npix}")
    print(f"  pixels differing >1:             {(diff>1).any(axis=2).sum()}/{npix}")
    print(f"  pixels differing >2:             {(diff>2).any(axis=2).sum()}/{npix}")
    print(f"  max channel diff: {diff.max()}   mean: {diff.mean():.5f}")

    # Where do the differences live? (expect: concentrated at the borders)
    ydiff = (diff > 0).any(axis=2)
    h, w = ydiff.shape
    border = np.zeros_like(ydiff); m = size[0] // 2
    border[:m, :] = border[-m:, :] = border[:, :m] = border[:, -m:] = True
    n_diff = ydiff.sum()
    if n_diff:
        print(f"  of differing pixels, { (ydiff & border).sum() }/{n_diff} are within "
              f"{m}px of a border")

    cv2.imwrite("frame0_reversed_filter_blur.png", recomputed)
    print("\nWrote frame0_reversed_filter_blur.png")


if __name__ == "__main__":
    main()
