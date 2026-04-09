#!/bin/bash
# Single bb prove instance. Witness prep for frame N+1 runs in the background
# while frame N is being proved, hiding prep latency behind proving time.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_FRAMES="${1:-}"
VIDEO_BLURRING_DIR="$SCRIPT_DIR/../video_blurring"
INPUT_FILES_DIR="$SCRIPT_DIR/../video_decompose_script/outputs/prover_input"
INPUT_FILES_DIR_ABS=$(realpath "$INPUT_FILES_DIR")

# 2 witness slots: current (proving) and next (being prepared)
WITNESS_CUR="$VIDEO_BLURRING_DIR/target/witness_cur.gz"
WITNESS_NXT="$VIDEO_BLURRING_DIR/target/witness_nxt.gz"

# prepare_witness_job: isolated per-frame job directory, no shared Prover.toml.
prepare_witness_job() {
    local frame_file="$1"
    local witness_out="$2"
    local job_dir="$3"

    mkdir -p "$job_dir/target"
    cp "$frame_file" "$job_dir/Prover.toml"

    cd "$job_dir"
    "$CARGO_BIN" "gblur" 2>&1 \
        | grep -E "(Using matrix type|Image dimensions|matrix dimensions|r dimensions|LHS|RHS)"

    ln -sf "$VIDEO_BLURRING_DIR/Nargo.toml"                          "$job_dir/Nargo.toml"
    ln -sf "$VIDEO_BLURRING_DIR/src"                                  "$job_dir/src"
    ln -sf "$VIDEO_BLURRING_DIR/target/video_blurring.json"           "$job_dir/target/video_blurring.json"

    nargo execute > /dev/null 2>&1
    cp "$job_dir/target/video_blurring.gz" "$witness_out"
}

# --- collect frames ---
FRAMES=()
while IFS= read -r f; do FRAMES+=("$f"); done \
    < <(find "$INPUT_FILES_DIR_ABS" -name 'Prover_*.toml' | sort)
TOTAL=${#FRAMES[@]}

[ "$TOTAL" -eq 0 ] && { echo "No frames found in $INPUT_FILES_DIR_ABS"; exit 1; }

if [ -n "$MAX_FRAMES" ] && [ "$MAX_FRAMES" -lt "$TOTAL" ]; then
    FRAMES=("${FRAMES[@]:0:$MAX_FRAMES}")
    TOTAL=$MAX_FRAMES
fi

# --- one-time setup ---
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
echo "===== Building Rust binary ====="
cd "$WORKSPACE_ROOT" && RUSTFLAGS="-A warnings" cargo build --release 2>/dev/null
CARGO_BIN="$WORKSPACE_ROOT/target/release/generate_freivalds_inputs"

cd "$VIDEO_BLURRING_DIR"
[ ! -f ./Prover.toml ] && nargo check --overwrite
echo "===== Generating VK ====="
bb write_vk -b ./target/video_blurring.json -o ./target -c "$HOME/.bb-crs"

OVERALL_START=$(date +%s)
echo "Starting 1-bb pipelined batch processing ($TOTAL frames)..."
echo "---"

# --- prime: prepare witness for frame 0 ---
echo "Pre-computing witness for frame 1 of $TOTAL..."
prepare_witness_job "${FRAMES[0]}" "$WITNESS_CUR" "/tmp/vb_job_0"

FILE_COUNT=0

for (( i=0; i<TOTAL; i++ )); do
    FILE_START=$(date +%s)
    echo "Proving frame $((i+1)) of $TOTAL..."

    # Kick off witness prep for next frame in background
    PREP_PID=""
    if [ $((i+1)) -lt "$TOTAL" ]; then
        prepare_witness_job "${FRAMES[$((i+1))]}" "$WITNESS_NXT" "/tmp/vb_job_$((i+1))" &
        PREP_PID=$!
    fi

    # Prove and verify current frame
    OUT="$VIDEO_BLURRING_DIR/target/out_frame_$i"
    mkdir -p "$OUT"
    cd "$VIDEO_BLURRING_DIR"
    bb prove \
        -b ./target/video_blurring.json \
        -w "$WITNESS_CUR" \
        -o "$OUT" \
        --vk_path ./target/vk \
        -c "$HOME/.bb-crs"
    bb verify -p "$OUT/proof" -k ./target/vk -i "$OUT/public_inputs" -c "$HOME/.bb-crs"
    echo "   -> Frame $((i+1)) proved & verified"

    # Wait for next witness, then swap slots
    [ -n "$PREP_PID" ] && wait "$PREP_PID"
    TMP="$WITNESS_CUR"; WITNESS_CUR="$WITNESS_NXT"; WITNESS_NXT="$TMP"

    FILE_END=$(date +%s)
    FILE_ELAPSED=$((FILE_END - FILE_START))
    echo "   Frame complete! Time: $((FILE_ELAPSED/60))m $((FILE_ELAPSED%60))s"
    echo "---"
    (( FILE_COUNT++ ))
done

OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$((OVERALL_END - OVERALL_START))
echo "Batch processing finished."
echo "Total frames processed: $FILE_COUNT"
echo "Total time: $((OVERALL_ELAPSED/60))m $((OVERALL_ELAPSED%60))s"
