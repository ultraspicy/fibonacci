#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

D=2764800  # 1280 x 720 x 3 (RGB)
E=8        # 8-bit pixels

echo "==> Generating ${D}-pixel images (max value 2^${E} = $((2**E)))..."
python3 genpic.py orig   $D $E
python3 genpic.py edited $D $E

echo "==> Building and running VerITAS prover/verifier..."
cargo run --release --example veritas

echo "==> Done."
