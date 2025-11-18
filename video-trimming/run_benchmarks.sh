#!/bin/bash

# This file runs the benchmarks contained in this directory, which benchmark the prover/verification
# time for our signatures based on polynomial commitments. It requires Rust nightly.

# Disable Rust build warnings so just the stats get printed out.
export RUSTFLAGS="-A warnings"

echo -e "\033[0;32m===== Running signature outsourcing benchmarks =====\033[0m"
cargo run --release --bin outsourced_signature_benchmarks

echo -e "\033[0;32m===== Running multilinear single block inclusion benchmarks =====\033[0m"
cargo run --release --bin video_trimming_demo_multi

echo -e "\033[0;32m===== Running multilinear multi-block benchmarks =====\033[0m"
cargo run --release --bin sumcheck_redactable_signatures

echo -e "\033[0;32m===== Running univariate one-frame benchmarks =====\033[0m"
cargo run --release --bin video_trimming_demo --

echo -e "\033[0;32m===== Running univariate one-frame benchmarks =====\033[0m"
cargo run --release --bin video_trimming_demo -- --use-long-segment