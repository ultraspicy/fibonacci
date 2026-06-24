"""
Reverse-engineer the linear filter that ffmpeg's downscale applies, then
re-apply it and measure the gap -- the resize analogue of reverse_ffmpeg_filter.py.

A resize is a separable linear resampling: resized = Rv @ orig @ Rh^T, where
Rv (dst_h x src_h) and Rh (dst_w x src_w) are the vertical/horizontal resampling
matrices. We recover each by resizing an IDENTITY image (each row/col is an
impulse -> one ffmpeg call yields the whole matrix), in 16-bit so weights are
exact. Done per channel since the RGB scaling path can differ.

IMPORTANT choice of scaler:
  - ffmpeg `area` (2x -> 2x2 box average) is a genuine LINEAR operator: its
    impulse response reproduces its action on real images -> reverse-engineers
    cleanly (max~1, mean~0.1).
  - ffmpeg `fast_bilinear` (the low-quality scaler the Rust mimics) is NOT
    cleanly linear: its impulse response is box-average, yet it differs from
    box-average on dense images by up to ~57/255. It cannot be captured by any
    fixed linear filter. We therefore target `area`; we also print the gap vs a
    fast_bilinear reference to show why it's the wrong target for a linear proof.
"""
import cv2
import numpy as np
import subprocess
import warnings

# Spurious "divide by zero in matmul" false alarm from some OpenBLAS builds on
# sparse (mostly-zero) matrices; the results are correct.
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*matmul.*")

ORIG_PATH = "frame0_original.png"
FLAG = "area"            # the clean, genuinely-linear downscaler


def _scale_png16(img16, out_w, out_h, flag=FLAG):
    """Scale a 16-bit image with ffmpeg and return float weights in [0,1]."""
    cv2.imwrite("/tmp/_rs_in.png", img16)
    pixfmt = "gray16le" if img16.ndim == 2 else "rgb48le"
    subprocess.run(
        ["ffmpeg", "-y", "-i", "/tmp/_rs_in.png",
         "-vf", f"scale={out_w}:{out_h}:flags={flag}",
         "-pix_fmt", pixfmt, "/tmp/_rs_out.png"],
        capture_output=True, check=True)
    return cv2.imread("/tmp/_rs_out.png", cv2.IMREAD_UNCHANGED).astype(np.float64) / 60000.0


def reverse_ffmpeg_resize_filter(src_n, dst_n, axis, channel):
    """Recover the (dst_n x src_n) resampling matrix for one axis & channel."""
    I = np.zeros((src_n, src_n, 3), np.uint16)
    idx = np.arange(src_n)
    I[idx, idx, channel] = 60000
    if axis == "h":                                   # width src_n -> dst_n
        out = _scale_png16(I, dst_n, src_n)[:, :, channel]   # (src_n, dst_n)
        W = out.T.copy()
    else:                                             # height src_n -> dst_n
        out = _scale_png16(I, src_n, dst_n)[:, :, channel]   # (dst_n, src_n)
        W = out.copy()
    taps = int((np.abs(W) > 1e-4).sum(axis=1).max())
    return W, W.shape, taps


def apply_resize(channel, Rv, Rh):
    out = Rv @ channel.astype(np.float64) @ Rh.T
    return np.clip(np.round(out), 0, 255).astype(np.uint8)


def compare(name, a, b):
    diff = np.abs(a.astype(np.int32) - b.astype(np.int32))
    n = a.size
    mse = (diff.astype(np.float64) ** 2).mean()
    psnr = float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)
    print(f"  {name}: max={diff.max()} mean={diff.mean():.4f} "
          f"px>0={(diff>0).sum()}/{n} px>1={(diff>1).sum()} PSNR={psnr:.2f}dB")


def ffmpeg_reference(flag, out_w, out_h, save_path=None):
    out = save_path or "/tmp/_ref.png"
    subprocess.run(["ffmpeg", "-y", "-i", ORIG_PATH,
                    "-vf", f"scale={out_w}:{out_h}:flags={flag}", out],
                   capture_output=True, check=True)
    return cv2.imread(out)


def main():
    orig = cv2.imread(ORIG_PATH)
    assert orig is not None, f"missing {ORIG_PATH}"
    src_h, src_w = orig.shape[:2]
    dst_h, dst_w = src_h // 2, src_w // 2
    print(f"resize: {src_w}x{src_h} -> {dst_w}x{dst_h}  (flags={FLAG})")

    # 1. Recover the linear resampling matrices, per channel.
    print("\n=== Recovered linear resize filters (per channel) ===")
    mats = []
    names = ["B", "G", "R"]
    for ch in range(3):
        Rv, vshape, vt = reverse_ffmpeg_resize_filter(src_h, dst_h, "v", ch)
        Rh, hshape, ht = reverse_ffmpeg_resize_filter(src_w, dst_w, "h", ch)
        mats.append((Rv, Rh))
        print(f"channel {names[ch]}: Rv {vshape[0]}x{vshape[1]} ({vt} taps/row), "
              f"Rh {hshape[0]}x{hshape[1]} ({ht} taps/row), rowsum~{Rv.sum(1).mean():.4f}")
    np.savez("ffmpeg_resize_matrices.npz",
             **{f"Rv{c}": mats[c][0] for c in range(3)},
             **{f"Rh{c}": mats[c][1] for c in range(3)})
    print("  saved -> ffmpeg_resize_matrices.npz")

    # 2. Re-resize the original with the recovered filter.
    recomputed = np.zeros((dst_h, dst_w, 3), np.uint8)
    for ch in range(3):
        Rv, Rh = mats[ch]
        recomputed[:, :, ch] = apply_resize(orig[:, :, ch], Rv, Rh)

    # 3. Compare vs ffmpeg's own `area` output (the clean linear target).
    ref = ffmpeg_reference(FLAG, dst_w, dst_h, save_path="frame0_ffmpeg_area_resize.png")
    print(f"\n=== Recovered-filter output vs ffmpeg {FLAG}, per channel ===")
    for ch in range(3):
        compare(f"channel {names[ch]}", recomputed[:, :, ch], ref[:, :, ch])
    diff = np.abs(recomputed.astype(np.int32) - ref.astype(np.int32))
    npix = dst_h * dst_w
    print("\n=== Whole image (vs area) ===")
    print(f"  pixels differing in any channel: {(diff>0).any(axis=2).sum()}/{npix}")
    print(f"  pixels differing >1:             {(diff>1).any(axis=2).sum()}/{npix}")
    print(f"  max channel diff: {diff.max()}   mean: {diff.mean():.5f}")

    # For contrast: gap vs the non-linear fast_bilinear scaler.
    fb = ffmpeg_reference("fast_bilinear", dst_w, dst_h)
    dfb = np.abs(recomputed.astype(np.int32) - fb.astype(np.int32))
    print(f"\n  (for contrast) same filter vs ffmpeg fast_bilinear: "
          f"max={dfb.max()} mean={dfb.mean():.4f}  <-- not cleanly linear, don't target this")

    cv2.imwrite("frame0_reversed_resize.png", recomputed)
    print(f"\nWrote (both {dst_w}x{dst_h}):")
    print("  frame0_ffmpeg_area_resize.png  <- ffmpeg area resize")
    print("  frame0_reversed_resize.png     <- reverse-engineered linear filter")


if __name__ == "__main__":
    main()
