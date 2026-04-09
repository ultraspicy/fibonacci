#!/bin/bash
# 4 parallel bb prove instances with NUMA pinning for AMD EPYC (2-socket).
# Processes frames in batches of 4: while proving batch N, prepares batch N+1.
#
# NUMA layout (AMD EPYC 7B13, 2 nodes):
#   node0: CPUs 0-23, 48-71  -> instances 0 and 1
#   node1: CPUs 24-47, 72-95 -> instances 2 and 3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_FRAMES="${1:-}"
VIDEO_BLURRING_DIR="$SCRIPT_DIR/../video_blurring"
INPUT_FILES_DIR="$SCRIPT_DIR/../video_decompose_script/outputs/prover_input"
INPUT_FILES_DIR_ABS=$(realpath "$INPUT_FILES_DIR")

N=4  # number of parallel bb prove instances

# 2N witness slots: current batch (0..N-1) and next batch (N..2N-1)
WITNESSES=()
for (( j=0; j<2*N; j++ )); do
    WITNESSES+=("$VIDEO_BLURRING_DIR/target/witness_${j}.gz")
done

# NUMA node assignment per instance index (0-indexed)
# Adjust if your NUMA layout differs (check: numactl --hardware)
numa_node() {
    local idx=$1
    if [ "$idx" -lt 2 ]; then echo 0; else echo 1; fi
}

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

    ln -sf "$VIDEO_BLURRING_DIR/Nargo.toml"                         "$job_dir/Nargo.toml"
    ln -sf "$VIDEO_BLURRING_DIR/src"                                 "$job_dir/src"
    ln -sf "$VIDEO_BLURRING_DIR/target/video_blurring.json"          "$job_dir/target/video_blurring.json"

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
echo "Starting 4-bb pipelined batch processing ($TOTAL frames, NUMA-pinned)..."
echo "---"

# --- prime: prepare first N witnesses in parallel ---
echo "Pre-computing witnesses for frames 1-$N of $TOTAL..."
PRIME_PIDS=()
for (( j=0; j<N && j<TOTAL; j++ )); do
    prepare_witness_job "${FRAMES[$j]}" "${WITNESSES[$j]}" "/tmp/vb_job_$j" &
    PRIME_PIDS+=($!)
done
for pid in "${PRIME_PIDS[@]}"; do wait "$pid"; done

# CUR_BASE: start index into WITNESSES for the current batch (0 or N)
CUR_BASE=0
FILE_COUNT=0

for (( i=0; i<TOTAL; i+=N )); do
    FILE_START=$(date +%s)
    BATCH_END=$(( i+N < TOTAL ? i+N : TOTAL ))
    BATCH_SIZE=$(( BATCH_END - i ))
    NXT_BASE=$(( (CUR_BASE + N) % (2*N) ))

    echo "Proving frames $((i+1))-$BATCH_END of $TOTAL..."

    # Kick off witness prep for next N frames in parallel
    PREP_PIDS=()
    for (( j=0; j<N; j++ )); do
        NEXT_IDX=$(( i + N + j ))
        if [ "$NEXT_IDX" -lt "$TOTAL" ]; then
            SLOT=$(( NXT_BASE + j ))
            prepare_witness_job "${FRAMES[$NEXT_IDX]}" "${WITNESSES[$SLOT]}" \
                "/tmp/vb_job_$NEXT_IDX" &
            PREP_PIDS+=($!)
        fi
    done

    # Prove all frames in the current batch in parallel, NUMA-pinned
    PROVE_PIDS=()
    for (( j=0; j<BATCH_SIZE; j++ )); do
        FRAME_IDX=$(( i + j ))
        SLOT=$(( CUR_BASE + j ))
        OUT="$VIDEO_BLURRING_DIR/target/out_frame_$FRAME_IDX"
        mkdir -p "$OUT"
        NODE=$(numa_node $j)
        (
            cd "$VIDEO_BLURRING_DIR"
            numactl --cpunodebind="$NODE" --membind="$NODE" \
                bb prove \
                    -b ./target/video_blurring.json \
                    -w "${WITNESSES[$SLOT]}" \
                    -o "$OUT" \
                    --vk_path ./target/vk \
                    -c "$HOME/.bb-crs"
            numactl --cpunodebind="$NODE" --membind="$NODE" \
                bb verify -p "$OUT/proof" -k ./target/vk -i "$OUT/public_inputs" \
                    -c "$HOME/.bb-crs"
            echo "   -> Frame $((FRAME_IDX+1)) proved & verified"
        ) &
        PROVE_PIDS+=($!)
    done

    # Wait for all provers
    for pid in "${PROVE_PIDS[@]}"; do wait "$pid"; done

    # Wait for witness prep before rotating
    for pid in "${PREP_PIDS[@]}"; do wait "$pid"; done

    CUR_BASE=$NXT_BASE
    FILE_END=$(date +%s)
    FILE_ELAPSED=$((FILE_END - FILE_START))
    echo "   $BATCH_SIZE frame(s) complete! Time: $((FILE_ELAPSED/60))m $((FILE_ELAPSED%60))s"
    echo "---"
    (( FILE_COUNT += BATCH_SIZE ))
done

OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$((OVERALL_END - OVERALL_START))
echo "Batch processing finished."
echo "Total frames processed: $FILE_COUNT"
echo "Total time: $((OVERALL_ELAPSED/60))m $((OVERALL_ELAPSED%60))s"
