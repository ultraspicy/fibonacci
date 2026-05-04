#!/bin/bash

# Parallel end-to-end pipeline for proving video frames.
#
# Usage: ./run_e2e_parallel.sh [max_frames] [max_parallel]
#   max_frames:   number of video frames to process (default: 20)
#   max_parallel: max concurrent proof jobs (default: all cores via nproc)
#
# Each job runs in an isolated temp directory so Prover.toml, witness (.gz),
# and proof files never collide. Read-only artifacts (compiled circuit .json,
# VK) are symlinked from the original circuit directories.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_FRAMES="${1:-20}"
MAX_PARALLEL="${2:-$(nproc)}"

FREIVALDS_DIR="$SCRIPT_DIR/generate_freivalds_inputs"
VIDEO_BLURRING_DIR="$SCRIPT_DIR/video_blurring"
NON_KEYFRAME_DIR="$SCRIPT_DIR/non_keyframe_edits"
INPUT_DIR="$SCRIPT_DIR/video_decompose_script/outputs/prover_input"
STATS_FILE="$SCRIPT_DIR/video_decompose_script/outputs/video_decomposition/decomposition_stats.json"

RUST_BINARY="$(dirname "$SCRIPT_DIR")/target/release/generate_freivalds_inputs"

ms() { python3 -c "import time; print(int(time.time() * 1000))"; }

# Temp dirs for per-job result and log files; cleaned up on exit
RESULTS_DIR=$(mktemp -d)
LOG_DIR=$(mktemp -d)
trap 'rm -rf "$RESULTS_DIR" "$LOG_DIR"' EXIT

# ── Pre-flight: build Rust binary once ──────────────────────────────────────
echo "===== Building Rust binary ====="
RUSTFLAGS="-A warnings" cargo build --release -q \
    --manifest-path "$(dirname "$SCRIPT_DIR")/Cargo.toml" \
    -p generate_freivalds_inputs
cd "$SCRIPT_DIR"

# ── Pre-flight: generate VKs once (shared read-only) ────────────────────────
echo "===== Generating VKs ====="
bb write_vk -b "$VIDEO_BLURRING_DIR/target/video_blurring.json" \
    -o "$VIDEO_BLURRING_DIR/target" -c "$HOME/.bb-crs" 2>&1 | grep -E "VK saved|error" || true
bb write_vk -b "$NON_KEYFRAME_DIR/target/non_keyframe_edits.json" \
    -o "$NON_KEYFRAME_DIR/target" -c "$HOME/.bb-crs" 2>&1 | grep -E "VK saved|error" || true

# ── Parse keyframe indices ───────────────────────────────────────────────────
KEYFRAME_INDICES=$(python3 -c "
import json
with open('$STATS_FILE') as f:
    stats = json.load(f)
print(' '.join(str(k['index']) for k in stats['keyframes']))
")

is_keyframe() {
    local idx=$1
    for kf in $KEYFRAME_INDICES; do
        [[ "$idx" -eq "$kf" ]] && return 0
    done
    return 1
}

echo ""
echo "Keyframes at indices: $KEYFRAME_INDICES"
echo "Processing first $MAX_FRAMES frames ($(( MAX_FRAMES * 3 )) channel proofs), $MAX_PARALLEL parallel jobs"
echo "================================================================"

# ── Per-job worker ───────────────────────────────────────────────────────────
# Each job gets its own temp workspace so nothing is shared across jobs.
#
# Workspace layout:
#   $job_dir/
#     Prover.toml          ← unique input (written by Rust binary)
#   $job_dir/circuit/
#     Nargo.toml           ← copy (nargo needs this to find the package name)
#     src/                 ← symlink to original (read-only, never written)
#     target/
#       <circuit>.json     ← symlink to compiled artifact (read-only)
#       vk                 ← symlink to verification key (read-only)
#       <circuit>.gz       ← written by nargo execute (unique per job)
#       proof              ← written by bb prove (unique per job)
#       public_inputs      ← written by bb prove (unique per job)

prove_job() {
    local frame_num=$1
    local channel=$2
    local frame_type=$3
    local input_file=$4
    local result_file="$RESULTS_DIR/${frame_num}_${channel}"
    local log_file="$LOG_DIR/${frame_num}_${channel}.log"

    local job_dir
    job_dir=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$job_dir'" RETURN

    local t_start
    t_start=$(ms)

    # 1. Generate Freivalds inputs into job_dir/Prover.toml.
    #    Keyframes:     Rust binary computes blur + Freivalds vectors for full frame.
    #    Non-keyframes: Rust binary computes real delta(frame[t], frame[t-1]) + Freivalds vectors.
    if [[ "$frame_type" == "keyframe" ]]; then
        cp "$input_file" "$job_dir/Prover.toml"
        cd "$job_dir"
        "$RUST_BINARY" gblur > /dev/null 2>>"$log_file"
    else
        local prev_frame_num=$(( frame_num - 1 ))
        local prev_input="$INPUT_DIR/Prover_$(printf '%04d' "$prev_frame_num")_${channel}.toml"
        cp "$input_file" "$job_dir/Prover.toml"
        cd "$job_dir"
        local delta_rc=0
        "$RUST_BINARY" delta "$prev_input" > /dev/null 2>>"$log_file" || delta_rc=$?
        if [[ $delta_rc -eq 2 ]]; then
            # Delta too large — Prover.toml still has keyframe data; run as keyframe instead.
            frame_type="keyframe"
            "$RUST_BINARY" gblur > /dev/null 2>>"$log_file"
        elif [[ $delta_rc -ne 0 ]]; then
            exit $delta_rc
        fi
    fi

    # 2. Set up an isolated nargo workspace.
    if [[ "$frame_type" == "keyframe" ]]; then
        local circuit_name="video_blurring"
        local base_dir="$VIDEO_BLURRING_DIR"
    else
        local circuit_name="non_keyframe_edits"
        local base_dir="$NON_KEYFRAME_DIR"
    fi

    local circuit_dir="$job_dir/circuit"
    mkdir -p "$circuit_dir/target"

    cp "$base_dir/Nargo.toml" "$circuit_dir/Nargo.toml"
    ln -s "$base_dir/src"                              "$circuit_dir/src"
    ln -s "$base_dir/target/${circuit_name}.json"      "$circuit_dir/target/${circuit_name}.json"
    ln -s "$base_dir/target/vk"                        "$circuit_dir/target/vk"

    # Prover.toml was updated by the Rust binary in job_dir; move it into the circuit workspace
    cp "$job_dir/Prover.toml" "$circuit_dir/Prover.toml"

    # 3. Witness generation
    local w_start w_end
    w_start=$(ms)
    cd "$circuit_dir"
    nargo execute > /dev/null 2>>"$log_file"
    w_end=$(ms)

    # 4. Proof generation
    local p_start p_end
    p_start=$(ms)
    bb prove \
        -b "./target/${circuit_name}.json" \
        -w "./target/${circuit_name}.gz" \
        -o "./target" \
        --vk_path "./target/vk" \
        -c "$HOME/.bb-crs" > /dev/null 2>>"$log_file"
    p_end=$(ms)

    local witness_ms=$(( w_end - w_start ))
    local prove_ms=$(( p_end - p_start ))
    local total_ms=$(( p_end - t_start ))

    # Write result for aggregation (tab-separated)
    printf "%s\t%s\t%s\t%d\t%d\t%d\n" \
        "$(printf '%04d' "$frame_num")" "$channel" "$frame_type" \
        "$witness_ms" "$prove_ms" "$total_ms" \
        > "$result_file"
}

# ── Job pool (named-pipe semaphore, works on bash 3.2+) ─────────────────────
# A named pipe is pre-filled with MAX_PARALLEL tokens (newlines).
# Each job reads one token before starting (blocks if pool is empty)
# and writes one back when done — naturally limits concurrency.
SEMAPHORE=$(mktemp -u)
mkfifo "$SEMAPHORE"
exec 3<>"$SEMAPHORE"
rm "$SEMAPHORE"  # fd 3 keeps it alive; no need for the path
for (( i=0; i<MAX_PARALLEL; i++ )); do echo >&3; done

OVERALL_START=$(date +%s)

for (( frame_num=0; frame_num<MAX_FRAMES; frame_num++ )); do
    if is_keyframe "$frame_num"; then
        frame_type="keyframe"
    else
        frame_type="non-keyframe"
    fi

    for channel in B G R; do
        input_file="$INPUT_DIR/Prover_$(printf '%04d' "$frame_num")_${channel}.toml"
        [[ -f "$input_file" ]] || continue

        read -u 3  # acquire a token (blocks when MAX_PARALLEL jobs are running)
        ( trap 'echo >&3' EXIT; prove_job "$frame_num" "$channel" "$frame_type" "$input_file" ) &
    done
done

# Wait for all remaining jobs
wait

OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$(( OVERALL_END - OVERALL_START ))

# ── Print results ─────────────────────────────────────────────────────────────
printf "\n%-20s %-12s %10s %10s %10s\n" "Frame" "Type" "Witness(s)" "Prove(s)" "Total(s)"
echo "----------------------------------------------------------------"

FRAME_COUNT=0
KEYFRAME_PROOFS=0
NONKEYFRAME_PROOFS=0

# Sort results by frame/channel so output is ordered
for result_file in $(ls "$RESULTS_DIR" | sort); do
    IFS=$'\t' read -r frame_id channel frame_type witness_ms prove_ms total_ms \
        < "$RESULTS_DIR/$result_file"

    printf "%-20s %-12s %10.1f %10.1f %10.1f\n" \
        "${frame_id}_${channel}" "$frame_type" \
        "$(echo "scale=1; $witness_ms/1000" | bc)" \
        "$(echo "scale=1; $prove_ms/1000" | bc)" \
        "$(echo "scale=1; $total_ms/1000" | bc)"

    (( FRAME_COUNT += 1 ))
    if [[ "$frame_type" == "keyframe" ]]; then
        (( KEYFRAME_PROOFS += 1 ))
    else
        (( NONKEYFRAME_PROOFS += 1 ))
    fi
done

echo "================================================================"
echo "Total proofs:       $FRAME_COUNT"
echo "  Keyframe proofs:  $KEYFRAME_PROOFS"
echo "  Non-keyframe:     $NONKEYFRAME_PROOFS"
echo "Total time:         $((OVERALL_ELAPSED/60))m $((OVERALL_ELAPSED%60))s"

# Report any jobs that failed (log file exists but no result file)
FAILED=0
for log_file in "$LOG_DIR"/*.log; do
    [[ -f "$log_file" ]] || continue
    base=$(basename "$log_file" .log)
    if [[ ! -f "$RESULTS_DIR/$base" ]]; then
        if [[ $FAILED -eq 0 ]]; then
            echo ""
            echo "Failed jobs (check logs for details):"
        fi
        echo "  $base:"
        sed 's/^/    /' "$log_file"
        (( FAILED += 1 ))
    fi
done
[[ $FAILED -gt 0 ]] && echo "  ($FAILED jobs failed)" || true
