#!/bin/bash

# End-to-end pipeline for proving video frames.
# Keyframes use the dense video_blurring circuit.
# Non-keyframes use the sparse non_keyframe_edits circuit.
#
# Usage: ./run_e2e.sh [max_frames]
#   max_frames: number of video frames to process (default: 20)
#
# Timing is split into:
#   - Witness: cargo input gen + nargo execute (circuit constraint check)
#   - Prove:   bb prove (ZK proof generation)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_FRAMES="${1:-20}"

FREIVALDS_DIR="$SCRIPT_DIR/generate_freivalds_inputs"
VIDEO_BLURRING_DIR="$SCRIPT_DIR/video_blurring"
NON_KEYFRAME_DIR="$SCRIPT_DIR/non_keyframe_edits"
INPUT_DIR="$SCRIPT_DIR/video_decompose_script/outputs/prover_input"
STATS_FILE="$SCRIPT_DIR/video_decompose_script/outputs/video_decomposition/decomposition_stats.json"

# --- Parse keyframe indices from decomposition stats ---
KEYFRAME_INDICES=$(python3 -c "
import json
with open('$STATS_FILE') as f:
    stats = json.load(f)
print(' '.join(str(k['index']) for k in stats['keyframes']))
")

is_keyframe() {
    local idx=$1
    for kf in $KEYFRAME_INDICES; do
        if [ "$idx" -eq "$kf" ]; then return 0; fi
    done
    return 1
}

# --- One-time VK generation for both circuits ---
echo "===== Generating VKs ====="
cd "$VIDEO_BLURRING_DIR"
bb write_vk -b ./target/video_blurring.json -o ./target -c "$HOME/.bb-crs" 2>&1 | grep -E "VK saved|error"
cd "$NON_KEYFRAME_DIR"
bb write_vk -b ./target/non_keyframe_edits.json -o ./target -c "$HOME/.bb-crs" 2>&1 | grep -E "VK saved|error"

echo ""
echo "Keyframes at indices: $KEYFRAME_INDICES"
echo "Processing first $MAX_FRAMES video frames ($(( MAX_FRAMES * 3 )) channel proofs)..."
echo "================================================================"
printf "%-20s %-12s %10s %10s %10s\n" "Frame" "Type" "Witness(s)" "Prove(s)" "Total(s)"
echo "----------------------------------------------------------------"

ms() { python3 -c "import time; print(int(time.time() * 1000))"; }

OVERALL_START=$(date +%s)
FRAME_COUNT=0
KEYFRAME_PROOFS=0
NONKEYFRAME_PROOFS=0

for (( frame_num=0; frame_num<MAX_FRAMES; frame_num++ )); do
    FRAME_ID=$(printf "%04d" $frame_num)

    if is_keyframe $frame_num; then
        FRAME_TYPE="keyframe"
    else
        FRAME_TYPE="non-keyframe"
    fi

    for CHANNEL in B G R; do
        INPUT_FILE="$INPUT_DIR/Prover_${FRAME_ID}_${CHANNEL}.toml"
        if [ ! -f "$INPUT_FILE" ]; then
            continue
        fi

        FRAME_LABEL="${FRAME_ID}_${CHANNEL}"
        FRAME_START=$(ms)  # milliseconds

        if [ "$FRAME_TYPE" = "keyframe" ]; then
            # --- Keyframe: dense video_blurring circuit ---

            # Setup (not measured): cargo input gen + file copy
            cp "$INPUT_FILE" "$FREIVALDS_DIR/Prover.toml"
            cd "$FREIVALDS_DIR"
            RUSTFLAGS="-A warnings" cargo run --release "gblur" > /dev/null 2>&1
            cp "$FREIVALDS_DIR/Prover.toml" "$VIDEO_BLURRING_DIR/Prover.toml"
            cd "$VIDEO_BLURRING_DIR"

            # Witness: nargo execute only
            W_START=$(ms)
            nargo execute > /dev/null 2>&1
            W_END=$(ms)
            WITNESS_MS=$(( W_END - W_START ))

            # Prove: bb prove only
            P_START=$(ms)
            bb prove \
                -b ./target/video_blurring.json \
                -w ./target/video_blurring.gz \
                -o ./target \
                --vk_path ./target/vk \
                -c "$HOME/.bb-crs" > /dev/null 2>&1
            P_END=$(ms)
            PROVE_MS=$(( P_END - P_START ))

            (( KEYFRAME_PROOFS++ ))

        else
            # --- Non-keyframe: sparse non_keyframe_edits circuit ---

            # Setup (not measured): generate inputs
            cd "$NON_KEYFRAME_DIR"
            python3 ./scripts/generate_inputs.py > /dev/null 2>&1

            # Witness: nargo execute only
            W_START=$(ms)
            nargo execute > /dev/null 2>&1
            W_END=$(ms)
            WITNESS_MS=$(( W_END - W_START ))

            # Prove: bb prove only
            P_START=$(ms)
            bb prove \
                -b ./target/non_keyframe_edits.json \
                -w ./target/non_keyframe_edits.gz \
                -o ./target \
                --vk_path ./target/vk \
                -c "$HOME/.bb-crs" > /dev/null 2>&1
            P_END=$(ms)
            PROVE_MS=$(( P_END - P_START ))

            (( NONKEYFRAME_PROOFS++ ))
        fi

        FRAME_END=$(ms)
        TOTAL_MS=$(( FRAME_END - FRAME_START ))

        printf "%-20s %-12s %10.1f %10.1f %10.1f\n" \
            "$FRAME_LABEL" \
            "$FRAME_TYPE" \
            "$(echo "scale=1; $WITNESS_MS/1000" | bc)" \
            "$(echo "scale=1; $PROVE_MS/1000" | bc)" \
            "$(echo "scale=1; $TOTAL_MS/1000" | bc)"

        (( FRAME_COUNT++ ))
    done
done

OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$(( OVERALL_END - OVERALL_START ))

echo "================================================================"
echo "Total proofs:       $FRAME_COUNT"
echo "  Keyframe proofs:  $KEYFRAME_PROOFS"
echo "  Non-keyframe:     $NONKEYFRAME_PROOFS"
echo "Total time:         $((OVERALL_ELAPSED/60))m $((OVERALL_ELAPSED%60))s"
