# noir-video-editing

Zero-knowledge proofs for verifiable video editing. Proves that a video has been correctly transformed (e.g. Gaussian blur) without revealing the original, using [Noir](https://noir-lang.org/) circuits and the [Barretenberg](https://github.com/AztecProtocol/barretenberg) backend.

## How it works

Each video frame is split into R, G, B channels and proved independently. Two circuit types handle different frame types:

- **Keyframes** — use the `video_blurring` circuit, which proves the full dense matrix multiplication `A × original ≈ edited` via Freivalds' check.
- **Non-keyframes** — use the `non_keyframe_edits` circuit, which only proves the sparse pixel deltas between consecutive frames, batched in groups of 10. ~8× faster and ~7× less memory than the keyframe circuit.

Small pixel differences (within threshold) between the mathematically computed blur and the actual video output are snapped to zero before proving, maximizing sparsity for non-keyframe proofs.

## Directory structure

```
video_decompose_script/     Decomposes a video into keyframes and delta frames,
                            extracts RGB channels, outputs Prover.toml inputs
generate_freivalds_inputs/  Rust: computes Freivalds inputs (blur matrix × image),
                            snaps small pixel diffs to zero for sparse batching
video_blurring/             Noir circuit for keyframes (dense Freivalds check)
non_keyframe_edits/         Noir circuit for non-keyframes (sparse delta batching)
naive_convolution_baseline/ Baseline naive convolution circuit (benchmarking only)
video_resizing/             Experimental resizing circuit
run_e2e.sh                  End-to-end script: routes each frame to the right circuit
```

## Prerequisites

- [`nargo`](https://noir-lang.org/docs/getting_started/installation/) — Noir compiler and executor
- [`bb`](https://github.com/AztecProtocol/barretenberg) — Barretenberg prover (UltraHonk)
- `Rust` / `cargo` — for `generate_freivalds_inputs`
- `Python 3` — for input generation scripts
- CRS file at `~/.bb-crs/bn254_g1.dat`

## Commands

### Prove a single keyframe

```bash
cd video_blurring

# 1. Generate Freivalds inputs from a raw frame
cp <path/to/Prover_NNNN_C.toml> ../generate_freivalds_inputs/Prover.toml
cd ../generate_freivalds_inputs
cargo run --release gblur
cp Prover.toml ../video_blurring/Prover.toml
cd ../video_blurring

# 2. Compile, prove, verify
./scripts/compile_and_run.sh
```

### Prove a single non-keyframe (sparse batching)

```bash
cd non_keyframe_edits
./scripts/compile_and_run.sh
```

### Run end-to-end for N video frames

Routes each frame to the correct circuit automatically, prints per-frame witness and prove times.

```bash
# From noir-video-editing/
./run_e2e.sh 20       # first 20 frames
./run_e2e.sh          # default: 20 frames
./run_e2e.sh 220      # all frames
```

### Run all frames (pipelined — ~2× faster)

Overlaps witness generation for frame N+1 with proof generation for frame N.

```bash
cd generate_freivalds_inputs
./loop_frames_pipelined.sh          # all 660 Prover.toml files
./loop_frames_pipelined.sh 10       # first 10 only
```

## Benchmarks (720×1280, Apple M-series, 14 threads)

| Circuit | Witness (nargo) | Prove (bb) | Total |
|---|---|---|---|
| Keyframe (dense) | ~25s | ~28s | ~55s |
| Non-keyframe (sparse) | ~4.5s | ~3.7s | ~8s |

For a 220-frame video (2 keyframes, 218 non-keyframes, 3 channels each):
- Sequential: ~95 min
- Pipelined: ~60 min
