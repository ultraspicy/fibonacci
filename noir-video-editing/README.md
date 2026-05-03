# noir-video-editing

Zero-knowledge proofs for verifiable video editing. Proves that a video has been correctly transformed (e.g. Gaussian blur) without revealing the original frames, using [Noir](https://noir-lang.org/) circuits and the [Barretenberg](https://github.com/AztecProtocol/barretenberg) UltraHonk prover.

## How it works

Each frame is split into R, G, B channels and proved independently. The core verification technique is **Freivalds' algorithm**: instead of redoing the full convolution inside the circuit, random vectors `r` and `s` are generated and used to check probabilistically that `A × original ≈ edited`, where `A` is the Gaussian blur matrix. This reduces circuit size from O(n²) to O(n).

Two circuits handle different frame types:

- **Keyframes** — use `video_blurring`, which proves the full dense Freivalds check over the entire frame.
- **Non-keyframes** — use `non_keyframe_edits`, which only proves the sparse pixel deltas between consecutive frames, batched in groups of 10. ~8× faster and ~7× less memory.

Small pixel differences between the mathematically computed blur and the actual video output (due to codec rounding) are snapped to zero before proving, maximizing sparsity for non-keyframe proofs.

## Directory structure

```
video_decompose_script/     Decomposes a video into keyframes and delta frames,
                            extracts RGB channels, outputs Prover.toml inputs
generate_freivalds_inputs/  Rust: computes blur matrix × image, generates Freivalds
                            vectors (r, s, rTA, As), snaps small diffs to zero
video_blurring/             Noir circuit for keyframes (dense Freivalds check)
non_keyframe_edits/         Noir circuit for non-keyframes (sparse delta batching)
naive_convolution_baseline/ Baseline naive convolution circuit (benchmarking only)
video_resizing/             Experimental resizing circuit
install.sh                  Installs all dependencies
run_e2e.sh                  End-to-end script: routes each frame to the right circuit
```

## Installation

```bash
./install.sh
```

This installs: `nargo` (Noir compiler), `bb` (Barretenberg prover), Rust/cargo, Python 3, OpenCV, and NumPy. It also compiles the Rust crate and Noir circuits. Run it once before anything else.

Manual prerequisite list if you prefer to install yourself:
- [`nargo`](https://noir-lang.org/docs/getting_started/installation/)
- [`bb`](https://github.com/AztecProtocol/barretenberg) — Barretenberg prover (UltraHonk)
- Rust/`cargo`
- Python 3 with `opencv-python` and `numpy`
- CRS file at `~/.bb-crs/bn254_g1.dat` (downloaded automatically on first `bb` run)

## Usage

### Step 1 — Decompose your video into frames

```bash
cd video_decompose_script
python3 video_frame_decomposer.py   # splits video → keyframes + delta PNGs
python3 png_to_matrix.py            # PNG → JSON matrices
python3 construct_prover_toml.py    # JSON → Prover.toml files for each frame/channel
```

Output lands in `video_decompose_script/outputs/`.

### Step 2 — Run the end-to-end pipeline

```bash
# From the project root:
./run_e2e.sh 20      # prove first 20 video frames (default)
./run_e2e.sh 220     # prove all 220 frames
```

For each frame this script:
1. Detects whether it is a keyframe or non-keyframe.
2. Runs `cargo run --release gblur` (Rust) to compute the blur matrix and Freivalds vectors.
3. Runs `nargo execute` (witness generation) then `bb prove` (ZK proof generation).
4. Prints a per-frame timing table.

### Step 3 — Pipelined run (~2× faster)

Overlaps witness generation for frame N+1 with proof generation for frame N:

```bash
cd generate_freivalds_inputs
./loop_frames_pipelined.sh        # all 660 Prover.toml files
./loop_frames_pipelined.sh 10     # first 10 only
```

### Prove a single keyframe manually

```bash
cp <path/to/Prover_NNNN_C.toml> generate_freivalds_inputs/Prover.toml
cd generate_freivalds_inputs && cargo run --release gblur
cp Prover.toml ../video_blurring/Prover.toml
cd ../video_blurring && ./scripts/compile_and_run.sh
```

### Prove a single non-keyframe manually

```bash
cd non_keyframe_edits
./scripts/compile_and_run.sh
```

## Benchmarks (720×1280, Apple M-series, 14 threads)

| Circuit | Witness (nargo) | Prove (bb) | Total |
|---|---|---|---|
| Keyframe (dense) | ~25s | ~28s | ~55s |
| Non-keyframe (sparse) | ~4.5s | ~3.7s | ~8s |

For a 220-frame video (2 keyframes, 218 non-keyframes, 3 channels each):

| Mode | Time |
|---|---|
| Sequential | ~95 min |
| Pipelined | ~60 min |
