"""
OPTION 1 (resize): reimplement the Rust CIRCUIT resize logic in Python and
compare directly to ffmpeg -- no reverse-engineering.

Rust (freivalds_vector_generator/src/main.rs, create_resize_matrix_impl),
FILTER_BITS = 16, dst = src/2:

  x_inc   = ((src << 16) / dst + 1) >> 1
  src_pos = (i * x_inc) >> 15
  xx      = (x_inc & 0xffff) * 2^16 / x_inc
  taps    = [2^16 - xx, xx, xx, xx] at src_pos..src_pos+3   (filter_size = 4)

For exact 2x: x_inc = 65536, src_pos = 2i, xx = 0  =>  weight 2^16 on src[2i],
i.e. POINT SAMPLING -- the output is orig[::2, ::2]. The horizontal matrix is
transposed (create_resizing_matrix honors need_transpose, unlike gblur).

  resized = V @ image @ H ,  divide by (2^16)^2

Then compare F_circuit(X) to ffmpeg's scalers (neighbor / fast_bilinear / area).
"""
import cv2
import numpy as np
import subprocess
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning)   # spurious sparse-matmul alarm

ORIG_PATH = "frame0_original.png"
FILTER_BITS = 16
SCALE = 1 << FILTER_BITS


def create_resize_matrix_impl(src_size, dst_size):
    """Exact port of the Rust create_resize_matrix_impl (dst x src)."""
    filter_size = 4
    M = np.zeros((dst_size, src_size), dtype=np.float64)
    x_inc = ((src_size << 16) // dst_size + 1) >> 1
    for i in range(dst_size):
        src_pos = (i * x_inc) >> 15
        xx_inc = x_inc & 0xffff
        xx = (xx_inc * SCALE) // x_inc
        for j in range(filter_size):
            coeff = (SCALE - xx) if j == 0 else xx
            src_idx = src_pos + j
            if src_idx < src_size:
                M[i, src_idx] = coeff
    return M


def create_resizing_matrix(src_size, dst_size, for_horizontal):
    M = create_resize_matrix_impl(src_size, dst_size)
    return M.T.copy() if for_horizontal else M


def ffmpeg_scale(flag, out_w, out_h, save=None):
    out = save or "/tmp/_r.png"
    subprocess.run(["ffmpeg", "-y", "-i", ORIG_PATH,
                    "-vf", f"scale={out_w}:{out_h}:flags={flag}", out],
                   capture_output=True, check=True)
    return cv2.imread(out)


def compare(name, a, b):
    diff = np.abs(a.astype(np.int32) - b.astype(np.int32))
    n = a.size
    mse = (diff.astype(np.float64) ** 2).mean()
    psnr = float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)
    print(f"  {name:<28} max={diff.max():<4} mean={diff.mean():.4f} "
          f"exact={100*(~(diff>0).any(axis=2)).mean():5.1f}% PSNR={psnr:.2f}dB")


def main():
    orig = cv2.imread(ORIG_PATH)
    assert orig is not None, f"missing {ORIG_PATH}"
    src_h, src_w = orig.shape[:2]
    dst_h, dst_w = src_h // 2, src_w // 2

    V = create_resizing_matrix(src_h, dst_h, for_horizontal=False)   # 360 x 720
    H = create_resizing_matrix(src_w, dst_w, for_horizontal=True)    # 1280 x 640
    S2 = float(SCALE) ** 2
    print(f"=== Circuit resize (Rust reimpl) ===")
    print(f"  {src_w}x{src_h} -> {dst_w}x{dst_h}, FILTER_BITS={FILTER_BITS}")
    print(f"  V rowsum unique={np.unique(V.sum(1))}  H colsum unique={np.unique(H.sum(0))}")
    print(f"  -> exact 2x => weight {SCALE} on src[2i] (point sampling)")

    recomputed = np.zeros((dst_h, dst_w, 3), np.uint8)
    for ch in range(3):
        out = V @ orig[:, :, ch].astype(np.float64) @ H
        recomputed[:, :, ch] = np.clip(np.round(out / S2), 0, 255).astype(np.uint8)
    cv2.imwrite("frame0_circuit_resize.png", recomputed)

    # sanity: equals plain decimation orig[::2, ::2] ?
    dec = orig[::2, ::2]
    print(f"\n  circuit == orig[::2,::2] ? max diff = {np.abs(recomputed.astype(int)-dec.astype(int)).max()}")

    print("\n=== Circuit resize vs ffmpeg scalers ===")
    for flag in ["neighbor", "fast_bilinear", "area", "bilinear", "bicubic"]:
        compare(f"vs {flag}", recomputed, ffmpeg_scale(flag, dst_w, dst_h))

    print("\nWrote frame0_circuit_resize.png")


if __name__ == "__main__":
    main()
