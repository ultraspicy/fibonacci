#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_FRAMES="${1:-}"  # optional first arg limits number of frames processed
VIDEO_BLURRING_DIR="$SCRIPT_DIR/../video_blurring"
INPUT_FILES_DIR="$SCRIPT_DIR/../video_decompose_script/outputs/prover_input"
INPUT_FILES_DIR_ABS=$(realpath "$INPUT_FILES_DIR")

WITNESS_A="$VIDEO_BLURRING_DIR/target/witness_a.gz"
WITNESS_B="$VIDEO_BLURRING_DIR/target/witness_b.gz"

# Runs cargo (input gen) + nargo execute for a given frame file,
# saves the resulting witness to $2.
# Designed to run in a subshell (background &).
prepare_witness() {
    local frame_file="$1"
    local witness_out="$2"

    cp "$frame_file" "$SCRIPT_DIR/Prover.toml"
    cd "$SCRIPT_DIR"
    RUSTFLAGS="-A warnings" cargo run --release "gblur" 2>&1 \
        | grep -E "(Using matrix type|Image dimensions|matrix dimensions|r dimensions|LHS|RHS)"

    cd "$VIDEO_BLURRING_DIR"
    cp "$SCRIPT_DIR/Prover.toml" .
    nargo execute > /dev/null 2>&1
    cp ./target/video_blurring.gz "$witness_out"
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

# --- one-time VK setup ---
cd "$VIDEO_BLURRING_DIR"
if [ ! -f ./Prover.toml ]; then
    nargo check --overwrite
fi
echo "===== Generating VK ====="
bb write_vk -b ./target/video_blurring.json -o ./target -c "$HOME/.bb-crs"

OVERALL_START=$(date +%s)
echo "Starting pipelined batch processing ($TOTAL frames)..."
echo "---"

# --- prime the pipeline: prepare witness for frame 0 ---
echo "Pre-computing witness for frame 1 of $TOTAL..."
prepare_witness "${FRAMES[0]}" "$WITNESS_A"

CURRENT_WITNESS="$WITNESS_A"
NEXT_WITNESS="$WITNESS_B"
FILE_COUNT=0

for (( i=0; i<TOTAL; i++ )); do
    FRAME_NAME=$(basename "${FRAMES[$i]}")
    FILE_START=$(date +%s)

    echo "Proving $FRAME_NAME ($((i+1))/$TOTAL)..."

    # Kick off witness prep for the next frame in the background
    if [ $((i+1)) -lt "$TOTAL" ]; then
        prepare_witness "${FRAMES[$((i+1))]}" "$NEXT_WITNESS" &
        BG_PID=$!
    fi

    # Prove and verify current frame
    cd "$VIDEO_BLURRING_DIR"
    echo "   -> Proving..."
    time bb prove \
        -b ./target/video_blurring.json \
        -w "$CURRENT_WITNESS" \
        -o ./target \
        --vk_path ./target/vk \
        -c "$HOME/.bb-crs"

    echo "   -> Verifying..."
    time bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs -c "$HOME/.bb-crs"

    # Wait for background witness prep before swapping
    if [ $((i+1)) -lt "$TOTAL" ]; then
        wait "$BG_PID"
        # Swap slots
        TMP="$CURRENT_WITNESS"
        CURRENT_WITNESS="$NEXT_WITNESS"
        NEXT_WITNESS="$TMP"
    fi

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
