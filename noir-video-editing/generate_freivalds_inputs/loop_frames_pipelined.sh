#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_FRAMES="${1:-}"  # optional first arg limits number of frames processed
VIDEO_BLURRING_DIR="$SCRIPT_DIR/../video_blurring"
INPUT_FILES_DIR="$SCRIPT_DIR/../video_decompose_script/outputs/prover_input"
INPUT_FILES_DIR_ABS=$(realpath "$INPUT_FILES_DIR")

# bb manages its own thread pool and ignores OMP_NUM_THREADS;
# leave thread control to bb itself for now

# 4 witness slots: current pair (0,1) proving, next pair (2,3) being prepared
WITNESSES=(
    "$VIDEO_BLURRING_DIR/target/witness_0.gz"
    "$VIDEO_BLURRING_DIR/target/witness_1.gz"
    "$VIDEO_BLURRING_DIR/target/witness_2.gz"
    "$VIDEO_BLURRING_DIR/target/witness_3.gz"
)

# prepare_witness_job: isolated per-frame job directory so two jobs can run in
# parallel without Prover.toml races.
#   $1 = frame Prover.toml
#   $2 = witness output path
#   $3 = job working directory (unique per frame)
prepare_witness_job() {
    local frame_file="$1"
    local witness_out="$2"
    local job_dir="$3"

    mkdir -p "$job_dir/target"

    # Frame-specific Prover.toml — no shared state with other jobs
    cp "$frame_file" "$job_dir/Prover.toml"

    # Run the pre-built binary from the job dir (reads/writes ./Prover.toml)
    cd "$job_dir"
    "$CARGO_BIN" "gblur" 2>&1 \
        | grep -E "(Using matrix type|Image dimensions|matrix dimensions|r dimensions|LHS|RHS)"

    # Symlink the Noir project files so nargo can run without recompiling.
    # target/ stays job-local so the witness output is isolated.
    ln -sf "$VIDEO_BLURRING_DIR/Nargo.toml" "$job_dir/Nargo.toml"
    ln -sf "$VIDEO_BLURRING_DIR/src"         "$job_dir/src"
    ln -sf "$VIDEO_BLURRING_DIR/target/video_blurring.json" \
           "$job_dir/target/video_blurring.json"

    nargo execute > /dev/null 2>&1
    cp "$job_dir/target/video_blurring.gz" "$witness_out"
}

# --- collect frames ---
FRAMES=()
while IFS= read -r f; do
    FRAMES+=("$f")
done < <(find "$INPUT_FILES_DIR_ABS" -name 'Prover_*.toml' | sort)
TOTAL=${#FRAMES[@]}

if [ "$TOTAL" -eq 0 ]; then
    echo "No frames found in $INPUT_FILES_DIR_ABS"
    exit 1
fi

if [ -n "$MAX_FRAMES" ] && [ "$MAX_FRAMES" -lt "$TOTAL" ]; then
    FRAMES=("${FRAMES[@]:0:$MAX_FRAMES}")
    TOTAL=$MAX_FRAMES
fi

# --- one-time cargo build so every job calls the binary directly ---
# Must build from the workspace root (fibonacci/) where the root Cargo.toml lives;
# the binary lands in <workspace_root>/target/release/
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
echo "===== Building Rust binary ====="
cd "$WORKSPACE_ROOT"
RUSTFLAGS="-A warnings" cargo build --release 2>/dev/null
CARGO_BIN="$WORKSPACE_ROOT/target/release/generate_freivalds_inputs"

# --- one-time VK setup ---
cd "$VIDEO_BLURRING_DIR"
if [ ! -f ./Prover.toml ]; then
    nargo check --overwrite
fi
echo "===== Generating VK ====="
bb write_vk -b ./target/video_blurring.json -o ./target -c "$HOME/.bb-crs"

OVERALL_START=$(date +%s)
echo "Starting 2-wide pipelined batch processing ($TOTAL frames)..."
echo "---"

# --- prime the pipeline: prepare witnesses for frames 0 and 1 in parallel ---
echo "Pre-computing witnesses for frames 1-2 of $TOTAL..."
prepare_witness_job "${FRAMES[0]}" "${WITNESSES[0]}" "/tmp/vb_job_0" &
PRIME_PID0=$!
if [ "$TOTAL" -gt 1 ]; then
    prepare_witness_job "${FRAMES[1]}" "${WITNESSES[1]}" "/tmp/vb_job_1" &
    wait "$PRIME_PID0" $!
else
    wait "$PRIME_PID0"
fi

CUR_SLOT=0
FILE_COUNT=0

for (( i=0; i<TOTAL; i+=2 )); do
    FILE_START=$(date +%s)

    W_CUR0="${WITNESSES[$CUR_SLOT]}"
    W_CUR1="${WITNESSES[$(( CUR_SLOT + 1 ))]}"
    NXT_SLOT=$(( (CUR_SLOT + 2) % 4 ))
    W_NXT0="${WITNESSES[$NXT_SLOT]}"
    W_NXT1="${WITNESSES[$(( NXT_SLOT + 1 ))]}"

    echo "Proving frames $((i+1))-$((i+2)) of $TOTAL..."

    # Kick off witness prep for next two frames in parallel (each job isolated)
    PREP_PIDS=()
    if [ $((i+2)) -lt "$TOTAL" ]; then
        prepare_witness_job "${FRAMES[$((i+2))]}" "$W_NXT0" "/tmp/vb_job_$((i+2))" &
        PREP_PIDS+=($!)
    fi
    if [ $((i+3)) -lt "$TOTAL" ]; then
        prepare_witness_job "${FRAMES[$((i+3))]}" "$W_NXT1" "/tmp/vb_job_$((i+3))" &
        PREP_PIDS+=($!)
    fi

    # Prove frame i — per-frame output dir to avoid proof file collision
    OUT0="$VIDEO_BLURRING_DIR/target/out_frame_$i"
    mkdir -p "$OUT0"
    (
        cd "$VIDEO_BLURRING_DIR"
        bb prove \
            -b ./target/video_blurring.json \
            -w "$W_CUR0" \
            -o "$OUT0" \
            --vk_path ./target/vk \
            -c "$HOME/.bb-crs"
        bb verify -p "$OUT0/proof" -k ./target/vk -i "$OUT0/public_inputs" -c "$HOME/.bb-crs"
        echo "   -> Frame $((i+1)) proved & verified"
    ) &
    PROVE_PID0=$!

    # Prove frame i+1 in parallel (if it exists)
    PROVE_PID1=""
    if [ $((i+1)) -lt "$TOTAL" ]; then
        OUT1="$VIDEO_BLURRING_DIR/target/out_frame_$((i+1))"
        mkdir -p "$OUT1"
        (
            cd "$VIDEO_BLURRING_DIR"
            bb prove \
                -b ./target/video_blurring.json \
                -w "$W_CUR1" \
                -o "$OUT1" \
                --vk_path ./target/vk \
                -c "$HOME/.bb-crs"
            bb verify -p "$OUT1/proof" -k ./target/vk -i "$OUT1/public_inputs" -c "$HOME/.bb-crs"
            echo "   -> Frame $((i+2)) proved & verified"
        ) &
        PROVE_PID1=$!
    fi

    # Wait for both provers
    wait "$PROVE_PID0"
    [ -n "$PROVE_PID1" ] && wait "$PROVE_PID1"

    # Wait for background witness prep before rotating slots
    for pid in "${PREP_PIDS[@]}"; do
        wait "$pid"
    done

    CUR_SLOT=$NXT_SLOT

    FILE_END=$(date +%s)
    FILE_ELAPSED=$((FILE_END - FILE_START))
    PAIR_COUNT=$(( i+2 <= TOTAL ? 2 : TOTAL - i ))
    echo "   $PAIR_COUNT frame(s) complete! Time: $((FILE_ELAPSED/60))m $((FILE_ELAPSED%60))s"
    echo "---"

    (( FILE_COUNT += PAIR_COUNT ))
done

OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$((OVERALL_END - OVERALL_START))
echo "Batch processing finished."
echo "Total frames processed: $FILE_COUNT"
echo "Total time: $((OVERALL_ELAPSED/60))m $((OVERALL_ELAPSED%60))s"
