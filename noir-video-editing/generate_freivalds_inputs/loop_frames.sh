#!/bin/bash

# --- Configuration ---
# Directory where the uniquely named TOML files are located
INPUT_FILES_DIR="../video_decompose_script/outputs/prover_input"

# Directory where the static input file will be created
OUTPUT_DIR="."

# The name of the static input file your Rust program reads
STATIC_INPUT_FILE="Prover.toml"

# --- Loop through all unique TOML files (e.g., Prover_0001.toml) ---
echo "Starting batch processing..."
echo "---"

# Find all TOML files and process them in a numerical order
find "$INPUT_FILES_DIR" -name 'Prover_*.toml' | sort | while read UNIQUE_FILE; do
    
    # 1. Get the simple filename for logging (e.g., Prover_0001.toml)
    FILE_NAME=$(basename "$UNIQUE_FILE")
    
    echo "Processing $FILE_NAME..."

    # 2. Copy the unique file and rename it to the static input file.
    #    This is your 'cp path_a/b path_c/d' step:
    #    cp outputs/prover_input/Prover_xxxx.toml outputs/Prover.toml
    cp "$UNIQUE_FILE" "$OUTPUT_DIR/$STATIC_INPUT_FILE"
    echo "   -> Copied input to $OUTPUT_DIR/$STATIC_INPUT_FILE"

    # 3. Execute your Rust program.
    #    It will read the newly copied Prover.toml.
    cargo run --release "resizing"
    cd ./../video_blurring
    ./scripts/compile_and_run.sh
    echo "   -> Execution complete."
    cd ./../generate_freivalds_inputs
    
    echo "---"

done

echo "✨ Batch processing finished for all files."