#!/bin/bash

# This file runs the benchmarks contained in this directory, which benchmark the constraint costs
# of representing messages as polynomials.

# Disable Rust build warnings so just the stats get printed out.
export RUSTFLAGS="-A warnings"

echo -e "\033[0;32m===== Running Poseidon Circuit Benchmarks =====\033[0m"
cargo run --release --bin poseidon_signature_verification

echo -e "\033[0;32m===== Running MLE Circuit Benchmarks =====\033[0m"
cargo run --release --bin multivariate_signature_verification

echo -e "\033[0;32m===== Running Horner's Circuit Benchmarks =====\033[0m"
cargo run --release --bin horners_signature_verification

echo -e "\033[0;32m===== Running Barycentric Circuit Benchmarks =====\033[0m"
cargo run --release --bin barycentric_signature_verification