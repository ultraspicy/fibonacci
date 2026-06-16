"""
Compare ZK-circuit Gaussian blur (sigma=10, radius=30, edge-clamp padding)
against FFmpeg gblur with lossless PNG output.
Sweeps sigma and steps to find the closest FFmpeg match.
"""
import cv2
import numpy as np
import subprocess
import os

ORIG_PATH = "frame0_original.png"
OUR_PATH  = "frame0_our_blur.png"


def ffmpeg_gblur_png(input_path, output_path, sigma, steps):
    """Apply FFmpeg gblur to a PNG and save as lossless PNG."""
    cmd = [
        "ffmpeg", "-y", "-i", input_path,
        "-vf", f"gblur=sigma={sigma}:steps={steps}",
        output_path
    ]
    subprocess.run(cmd, capture_output=True, check=True)


def compare(name_a, a, name_b, b):
    if a is None or b is None:
        print(f"{name_a} vs {name_b}: one file missing")
        return None
    diff = np.abs(a.astype(np.int32) - b.astype(np.int32))
    n_pix = a.shape[0] * a.shape[1]
    mean_d = diff.mean()
    print(f"{name_a} vs {name_b}:")
    print(f"  max={diff.max()}  mean={mean_d:.5f}  "
          f"px>0={(diff>0).any(axis=2).sum()}/{n_pix}  "
          f"px>1={(diff>1).any(axis=2).sum()}/{n_pix}")
    return mean_d


def main():
    our  = cv2.imread(OUR_PATH)
    assert our is not None, f"Missing {OUR_PATH}"

    # ── Existing reference files ──────────────────────────────────────────────
    print("=== Existing reference comparisons ===")
    compare("our_blur", our, "ffmpeg_blur",     cv2.imread("frame0_ffmpeg_blur.png"))
    compare("our_blur", our, "ffmpeg_lossless", cv2.imread("frame0_ffmpeg_blur_lossless.png"))
    compare("our_blur", our, "ffmpeg_rgb",      cv2.imread("frame0_ffmpeg_blur_rgb.png"))
    print()

    # ── Sweep FFmpeg sigma / steps ────────────────────────────────────────────
    print("=== FFmpeg gblur sweep (lossless PNG output) ===")
    sigmas     = [9.5, 10.0, 10.5]
    steps_list = [1, 2, 3, 4, 5, 6]

    best = {"tag": None, "mean": 1e9, "path": None}
    for sigma in sigmas:
        for steps in steps_list:
            tag = f"sigma{sigma}_steps{steps}"
            out = f"/tmp/ffmpeg_{tag}.png"
            try:
                ffmpeg_gblur_png(ORIG_PATH, out, sigma, steps)
                img = cv2.imread(out)
                mean_d = compare(f"our_blur", img, tag, our)
                if mean_d is not None and mean_d < best["mean"]:
                    best = {"tag": tag, "mean": mean_d, "path": out}
            except subprocess.CalledProcessError:
                print(f"  {tag}: FFmpeg failed")
    print()

    # ── Save the best ─────────────────────────────────────────────────────────
    if best["path"]:
        dest = "frame0_ffmpeg_best_lossless.png"
        import shutil
        shutil.copy(best["path"], dest)
        print(f"Best FFmpeg match: {best['tag']}  mean_diff={best['mean']:.5f}")
        print(f"Saved as {dest}")


if __name__ == "__main__":
    main()
