#!/bin/bash

# This runs all the different commands to compile, generate inputs and run
# a Noir script. This assumes that you are in the non_keyframe_edits directory
# and should be run as `./scripts/compile_and_run.sh`.

VMTOUCH="$(dirname "$0")/vmtouch"

echo -e "\033[0;32m===== Setting Up Proofs =====\033[0m"
# Produce the empty Prover.toml template only if it doesn't exist yet
if [ ! -f ./Prover.toml ]; then
    nargo check --overwrite
fi

# Populate the Prover.toml file with inputs
python3 ./scripts/generate_inputs.py

# Generate a witness
nargo execute > /dev/null 2>&1

# Generate VK once (only if it doesn't exist yet or circuit has changed)
echo -e "\033[0;32m===== Generating VK =====\033[0m"
bb write_vk -b ./target/non_keyframe_edits.json -o ./target -c $HOME/.bb-crs

# Pre-load large files into OS page cache to reduce I/O latency
echo -e "\033[0;32m===== Pre-loading Files into Page Cache =====\033[0m"
# "$VMTOUCH" ./target/non_keyframe_edits.json $HOME/.bb-crs/bn254_g1.dat
cat ./target/non_keyframe_edits.json > /dev/null
cat $HOME/.bb-crs/bn254_g1.dat > /dev/null

echo -e "\033[0;32m===== Timing Proof Generation =====\033[0m"
# Compute the proof using precomputed VK (proving key computed once per run)
# --disable_zk removes zero-knowledge overhead (safe for benchmarking)
time bb prove -b ./target/non_keyframe_edits.json -w ./target/non_keyframe_edits.gz -o ./target --vk_path ./target/vk -c $HOME/.bb-crs #--disable_zk

echo -e "\033[0;32m===== Timing verification =====\033[0m"
# Verify the proof
time bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs -c $HOME/.bb-crs #--disable_zk
