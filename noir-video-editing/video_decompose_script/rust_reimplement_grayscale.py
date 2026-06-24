"""
OPTION 1 (grayscale): reimplement the Rust CIRCUIT grayscale logic in Python and
compare directly to ffmpeg -- no reverse-engineering.

Rust (Spartan2 examples/implement_video_edit.rs), integer BT.601 luma:

  gray = (r*299 + g*587 + b*114) / 1000      (integer division = floor)

This is a pointwise linear map (no neighbors / boundary), so it should match
ffmpeg's integer BT.601 path bit-for-bit. We compare against:
  * ffmpeg `geq`     (same integer formula)  -> expect exact
  * ffmpeg `format=gray` (BT.601, own rounding) -> expect +-1
"""
import cv2
import numpy as np
import subprocess

ORIG_PATH = "frame0_original.png"


def circuit_grayscale(orig_bgr):
    B = orig_bgr[:, :, 0].astype(np.uint32)
    G = orig_bgr[:, :, 1].astype(np.uint32)
    R = orig_bgr[:, :, 2].astype(np.uint32)
    return ((R * 299 + G * 587 + B * 114) // 1000).astype(np.uint8)


def ffmpeg_gray(vf):
    subprocess.run(["ffmpeg", "-y", "-i", ORIG_PATH, "-vf", vf, "/tmp/_g.png"],
                   capture_output=True, check=True)
    return cv2.imread("/tmp/_g.png", cv2.IMREAD_GRAYSCALE)


def compare(name, a, b):
    diff = np.abs(a.astype(np.int32) - b.astype(np.int32))
    n = a.size
    mse = (diff.astype(np.float64) ** 2).mean()
    psnr = float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)
    print(f"  {name:<26} max={diff.max()} mean={diff.mean():.4f} "
          f"exact={100*(diff==0).mean():.1f}% ({(diff==0).sum()}/{n}) PSNR={psnr:.2f}dB")


def main():
    orig = cv2.imread(ORIG_PATH)
    assert orig is not None, f"missing {ORIG_PATH}"

    gray = circuit_grayscale(orig)
    cv2.imwrite("frame0_circuit_gray.png", gray)
    print("=== Circuit grayscale (Rust integer BT.601) vs ffmpeg ===")

    geq = ("format=rgb24,geq="
           "r='(299*r(X,Y)+587*g(X,Y)+114*b(X,Y))/1000':"
           "g='(299*r(X,Y)+587*g(X,Y)+114*b(X,Y))/1000':"
           "b='(299*r(X,Y)+587*g(X,Y)+114*b(X,Y))/1000'")
    compare("vs ffmpeg geq (integer)", gray, ffmpeg_gray(geq))
    compare("vs ffmpeg format=gray",   gray, ffmpeg_gray("format=gray"))

    print("\nWrote frame0_circuit_gray.png")


if __name__ == "__main__":
    main()
