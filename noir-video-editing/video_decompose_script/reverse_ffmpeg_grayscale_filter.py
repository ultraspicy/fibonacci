"""
Reverse-engineer the linear filter that ffmpeg's grayscale (format=gray) applies,
then re-apply it and measure the gap -- the grayscale analogue of
reverse_ffmpeg_filter.py / reverse_ffmpeg_resize_filter.py.

Grayscale is the simplest of the three: a POINTWISE linear map. Each output
pixel is gray = wR*R + wG*G + wB*B of that same pixel -- no neighbors, no
spatial kernel, no boundary. So the "filter" is just three weights (a 1x3
matrix), recovered here by least-squares over a random color probe.

We target two references:
  * ffmpeg `format=gray`  -- its own (BT.601, full-range) grayscale.
  * the Rust integer formula  (299*R + 587*G + 114*B)/1000  (BT.601), which
    ffmpeg can reproduce bit-exactly via `geq` (shown for contrast).
"""
import cv2
import numpy as np
import subprocess

ORIG_PATH = "frame0_original.png"


def _ffmpeg_gray(in_path, vf="format=gray"):
    subprocess.run(["ffmpeg", "-y", "-i", in_path, "-vf", vf, "/tmp/_g.png"],
                   capture_output=True, check=True)
    im = cv2.imread("/tmp/_g.png", cv2.IMREAD_GRAYSCALE)
    return im


def reverse_ffmpeg_grayscale_filter():
    """Recover (wR, wG, wB, bias) by least-squares over a random color probe."""
    rng = np.random.default_rng(0)
    probe_bgr = rng.integers(0, 256, size=(256, 256, 3), dtype=np.uint8)
    cv2.imwrite("/tmp/_probe.png", probe_bgr)
    gray = _ffmpeg_gray("/tmp/_probe.png").astype(np.float64).ravel()

    B = probe_bgr[:, :, 0].astype(np.float64).ravel()
    G = probe_bgr[:, :, 1].astype(np.float64).ravel()
    R = probe_bgr[:, :, 2].astype(np.float64).ravel()
    A = np.column_stack([R, G, B, np.ones_like(R)])          # [R G B 1]
    coef, *_ = np.linalg.lstsq(A, gray, rcond=None)          # wR, wG, wB, bias
    return coef


def apply_grayscale(orig_bgr, coef):
    wR, wG, wB, bias = coef
    B = orig_bgr[:, :, 0].astype(np.float64)
    G = orig_bgr[:, :, 1].astype(np.float64)
    R = orig_bgr[:, :, 2].astype(np.float64)
    out = wR * R + wG * G + wB * B + bias
    return np.clip(np.round(out), 0, 255).astype(np.uint8)


def compare(name, a, b):
    diff = np.abs(a.astype(np.int32) - b.astype(np.int32))
    n = a.size
    mse = (diff.astype(np.float64) ** 2).mean()
    psnr = float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)
    print(f"  {name}: max={diff.max()} mean={diff.mean():.4f} "
          f"px>0={(diff>0).sum()}/{n} exact={100*(diff==0).mean():.1f}% PSNR={psnr:.2f}dB")


def main():
    orig = cv2.imread(ORIG_PATH)
    assert orig is not None, f"missing {ORIG_PATH}"

    # 1. Recover the linear filter (3 weights + bias).
    coef = reverse_ffmpeg_grayscale_filter()
    wR, wG, wB, bias = coef
    print("=== Recovered linear grayscale filter ===")
    print(f"  filter size: 1x3 (pointwise)")
    print(f"  weights: R={wR:.5f}  G={wG:.5f}  B={wB:.5f}  bias={bias:.4f}")
    print(f"  (BT.601 reference: R=0.299  G=0.587  B=0.114)")

    # 2. Re-grayscale the original with the recovered filter.
    recomputed = apply_grayscale(orig, coef)

    # 3a. Compare vs ffmpeg's own format=gray.
    ref_gray = _ffmpeg_gray(ORIG_PATH)
    print("\n=== Recovered filter vs ffmpeg format=gray ===")
    compare("gray", recomputed, ref_gray)
    cv2.imwrite("frame0_ffmpeg_gray.png", ref_gray)
    cv2.imwrite("frame0_reversed_gray.png", recomputed)

    # 3b. For contrast: the exact Rust integer BT.601 formula, and ffmpeg geq.
    Bc = orig[:, :, 0].astype(np.uint32)
    Gc = orig[:, :, 1].astype(np.uint32)
    Rc = orig[:, :, 2].astype(np.uint32)
    rust = ((Rc * 299 + Gc * 587 + Bc * 114) // 1000).astype(np.uint8)
    geq_vf = ("format=rgb24,geq="
              "r='(299*r(X,Y)+587*g(X,Y)+114*b(X,Y))/1000':"
              "g='(299*r(X,Y)+587*g(X,Y)+114*b(X,Y))/1000':"
              "b='(299*r(X,Y)+587*g(X,Y)+114*b(X,Y))/1000'")
    ffmpeg_geq = _ffmpeg_gray(ORIG_PATH, vf=geq_vf)
    print("\n=== Exact integer BT.601 formula (Rust) ===")
    compare("ffmpeg geq vs Rust integer", ffmpeg_geq, rust)
    compare("recovered  vs Rust integer", recomputed, rust)

    print("\nWrote frame0_ffmpeg_gray.png and frame0_reversed_gray.png "
          f"(both {orig.shape[1]}x{orig.shape[0]})")


if __name__ == "__main__":
    main()
