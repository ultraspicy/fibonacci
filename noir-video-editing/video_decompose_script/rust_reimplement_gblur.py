"""
OPTION 1 (gblur): reimplement the Rust CIRCUIT logic in Python and compare its
output directly to ffmpeg -- no reverse-engineering.

In-circuit the blur is done in field elements (huge integers), so we can't export
the blurred image from the proof. Instead we replicate the exact circuit math
here (freivalds_vector_generator/src/main.rs):

  kernel:  phi = exp(-0.5/sigma^2 * i^2), i in [-30..30], normalized to sum 1,
           then fixed-point  k = floor(phi * 2^32)            (the Rust `as u64`)
  matrix:  size x size band matrix, edge-clamp boundary -- overflow kernel mass
           is folded into the first/last column (create_gblur_matrix)
  apply:   blurred = V @ image @ H        (V: height, H: width; no division)
  pixel:   divide by S^2  (S = sum of the floored kernel = each matrix row sum)

Then compare F_circuit(X) against ffmpeg gblur (sigma=10, steps=1).
Note: the circuit uses RADIUS 30, while ffmpeg's effective support is ~45, so the
truncated tails make this gap larger than the radius-80 reverse-engineered fit.
"""
import cv2
import numpy as np
import warnings

# Spurious "divide by zero / overflow in matmul" false alarm from OpenBLAS on
# sparse band matrices; results are correct.
warnings.filterwarnings("ignore", category=RuntimeWarning)

ORIG_PATH = "frame0_original.png"
BLUR_PATH = "frame0_ffmpeg_blur_lossless.png"
SIGMA = 10.0
RADIUS = 30
KERNEL_SCALE = 1 << 32


def fixed_point_kernel(sigma, radius):
    i = np.arange(-radius, radius + 1, dtype=np.float64)
    phi = np.exp(-0.5 / sigma ** 2 * i ** 2)
    phi /= phi.sum()
    return np.floor(phi * KERNEL_SCALE).astype(np.int64)   # Rust: (x * 2^32) as u64


def create_gblur_matrix(size, kernel, radius):
    """Exact port of Rust create_gblur_matrix: band matrix with edge-clamp folding."""
    klen = len(kernel)
    M = np.zeros((size, size), dtype=np.float64)
    for i in range(size):
        left_overflow = radius - i if i < radius else 0
        right_overflow = i + radius - size + 1 if i + radius >= size else 0
        left_mass = int(kernel[:left_overflow].sum()) if left_overflow else 0
        right_mass = int(kernel[klen - right_overflow:].sum()) if right_overflow else 0
        js = range(max(0, i - radius), min(i + radius, size - 1) + 1)
        for k_idx, j in enumerate(js):
            M[i, j] = kernel[left_overflow + k_idx]
        if left_overflow:
            M[i, 0] += left_mass
        if right_overflow:
            M[i, size - 1] += right_mass
    return M


def compare(name, a, b):
    diff = np.abs(a.astype(np.int32) - b.astype(np.int32))
    n = a.size
    mse = (diff.astype(np.float64) ** 2).mean()
    psnr = float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)
    print(f"  {name}: max={diff.max()} mean={diff.mean():.4f} "
          f"px>0={(diff>0).sum()}/{n} px>1={(diff>1).sum()} px>2={(diff>2).sum()} "
          f"exact={100*(diff==0).mean():.1f}% PSNR={psnr:.2f}dB")


def main():
    orig = cv2.imread(ORIG_PATH)
    blur = cv2.imread(BLUR_PATH)
    assert orig is not None and blur is not None, "missing input images"
    h, w = orig.shape[:2]

    kernel = fixed_point_kernel(SIGMA, RADIUS)
    S = int(kernel.sum())                       # each matrix row sums to S
    print(f"=== Circuit gblur (Rust reimpl) ===")
    print(f"  kernel: radius={RADIUS}, len={len(kernel)}, S=sum(floor(phi*2^32))={S}")
    print(f"  scale 2^32={KERNEL_SCALE}, S/2^32={S/KERNEL_SCALE:.8f} (floor loss)")

    V = create_gblur_matrix(h, kernel, RADIUS)
    H = create_gblur_matrix(w, kernel, RADIUS)
    S2 = float(S) ** 2

    # The gblur matrix is ASYMMETRIC at the boundary (overflow mass is folded into
    # one index only). The horizontal pass therefore needs H transposed. But the
    # Rust create_matrix passes need_transpose=true for the horizontal matrix while
    # create_gblur_matrix IGNORES it -> the circuit computes V @ X @ H, which is
    # wrong at the left/right edge columns. We report both.
    def run(use_transpose):
        out = np.zeros_like(blur)
        for ch in range(3):
            Hm = H.T if use_transpose else H
            blurred = V @ orig[:, :, ch].astype(np.float64) @ Hm
            out[:, :, ch] = np.clip(np.round(blurred / S2), 0, 255).astype(np.uint8)
        return out

    names = ["B", "G", "R"]
    npix = h * w
    for label, use_t in [("CIRCUIT as-written  V @ X @ H   ", False),
                         ("FIXED (transpose H) V @ X @ H^T ", True)]:
        rec = run(use_t)
        diff = np.abs(rec.astype(np.int32) - blur.astype(np.int32))
        print(f"\n=== {label} vs ffmpeg gblur ===")
        for ch in range(3):
            compare(f"channel {names[ch]}", rec[:, :, ch], blur[:, :, ch])
        print(f"  whole image: max={diff.max()} mean={diff.mean():.4f} "
              f"exact={100*(~(diff>0).any(axis=2)).mean():.1f}% "
              f">1={(diff>1).any(axis=2).sum()} >2={(diff>2).any(axis=2).sum()}")
        cv2.imwrite("frame0_circuit_blur.png" if not use_t
                    else "frame0_circuit_blur_fixed.png", rec)


if __name__ == "__main__":
    main()
