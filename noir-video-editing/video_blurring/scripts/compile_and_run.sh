#!/bin/bash

# This runs all the different commands to compile, generate inputs and run
# a Noir script. This assumes that you are in the video_blurring directory
# and should be run as `./scripts/compile_and_run.sh`.

VMTOUCH="$(dirname "$0")/vmtouch"

echo -e "\033[0;32m===== Setting Up Proofs =====\033[0m"
# Produce the empty Prover.toml template only if it doesn't exist yet
if [ ! -f ./Prover.toml ]; then
    nargo check --overwrite
fi

# Populate the Prover.toml file with inputs
# python3 ./scripts/generate_inputs.py
#RUSTFLAGS="-A warnings" cargo run --release --manifest-path ../generate_freivalds_inputs/Cargo.toml gblur

cp ../generate_freivalds_inputs/Prover.toml .

# Generate a witness
nargo execute > /dev/null 2>&1

# Generate VK once (only if it doesn't exist yet or circuit has changed)
if [ ! -f ./target/vk ]; then
    echo -e "\033[0;32m===== Generating VK (one-time setup) =====\033[0m"
    bb write_vk -b ./target/video_blurring.json -o ./target -c $HOME/.bb-crs
fi

# Pre-load large files into OS page cache to reduce I/O latency
echo -e "\033[0;32m===== Pre-loading Files into Page Cache =====\033[0m"
"$VMTOUCH" -t ./target/video_blurring.json $HOME/.bb-crs/bn254_g1.dat

echo -e "\033[0;32m===== Timing Proof Generation =====\033[0m"
# Compute the proof using precomputed VK (proving key computed once per run)
# --disable_zk removes zero-knowledge overhead (safe for benchmarking)
time bb prove -b ./target/video_blurring.json -w ./target/video_blurring.gz -o ./target --vk_path ./target/vk -c $HOME/.bb-crs #--disable_zk

echo -e "\033[0;32m===== Timing verification =====\033[0m"
# Verify the proof
# -i is public input path flag
time bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs -c $HOME/.bb-crs #--disable_zk
