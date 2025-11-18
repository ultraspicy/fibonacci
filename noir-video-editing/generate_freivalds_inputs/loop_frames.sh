#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Change to the generate_freivalds_inputs directory
cd "$SCRIPT_DIR"

# --- Configuration ---
INPUT_FILES_DIR="../video_decompose_script/outputs/prover_input"
STATIC_INPUT_FILE="Prover.toml"

# --- Start overall timer ---
OVERALL_START=$(date +%s)

echo "Starting batch processing..."
echo "Working directory: $(pwd)"
echo "---"

FILE_COUNT=0

# Convert to absolute path to avoid issues
INPUT_FILES_DIR_ABS=$(realpath "$INPUT_FILES_DIR")

# Find all TOML files and process them in numerical order
find "$INPUT_FILES_DIR_ABS" -name 'Prover_*.toml' | sort | while read UNIQUE_FILE; do
    
    FILE_START=$(date +%s)
    FILE_NAME=$(basename "$UNIQUE_FILE")
    
    echo "Processing $FILE_NAME..."

    # Step 1: Copy file to current directory (generate_freivalds_inputs)
    cp "$UNIQUE_FILE" "./$STATIC_INPUT_FILE"
    echo "   -> Copied to ./$STATIC_INPUT_FILE"

    # Step 2: Run cargo from current directory (generate_freivalds_inputs)
    echo "   -> Running cargo..."
    RUSTFLAGS="-A warnings" cargo run --release "gblur" 2>&1 | grep -E "(Using matrix type|Image dimensions|matrix dimensions|r dimensions|LHS|RHS)"
    
    # Step 3: Go to video_blurring directory and run the script
    echo "   -> Running video_blurring script..."
    cd ../video_blurring
    ./scripts/compile_and_run.sh
    
    # Return to generate_freivalds_inputs directory
    cd "$SCRIPT_DIR"
    
    FILE_END=$(date +%s)
    FILE_ELAPSED=$((FILE_END - FILE_START))
    FILE_MINUTES=$((FILE_ELAPSED / 60))
    FILE_SECONDS=$((FILE_ELAPSED % 60))
    
    echo "   ✅ Frame complete!"
    echo "   ⏱️  Time for $FILE_NAME: ${FILE_MINUTES}m ${FILE_SECONDS}s"
    echo "---"
    
    ((FILE_COUNT++))

done

OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$((OVERALL_END - OVERALL_START))
OVERALL_MINUTES=$((OVERALL_ELAPSED / 60))
OVERALL_SECONDS=$((OVERALL_ELAPSED % 60))

echo "✨ Batch processing finished for all files."
echo "📊 Total frames processed: $FILE_COUNT"
echo "⏱️  Total time: ${OVERALL_MINUTES}m ${OVERALL_SECONDS}s"