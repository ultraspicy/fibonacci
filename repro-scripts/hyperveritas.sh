#!/usr/bin/env bash
# Reproduce HyperVerITAS benchmarks from:
# "HyperVerITAS: Verifying Image Transformations at Scale on Boolean Hypercubes"
#
# Usage:
#   ./reproduce.sh           # full benchmark 
#   ./reproduce.sh --quick   # smoke test
#   ./reproduce.sh --setup   # install + setup only, no benchmarks
#
# Target platform: Ubuntu 24.04, Rust nightly, Python 3.12+
# Disk space: ~70 GB for full run; ~5 GB for quick mode

set -euo pipefail

QUICK=false
SETUP_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --quick)  QUICK=true ;;
    --setup)  SETUP_ONLY=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

log()  { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_DIR/run.log"; }
die()  { echo "ERROR: $*" >&2; exit 1; }
skip() { log "SKIP: $* (already installed)"; }

# ─── 1. System dependencies ──────────────────────────────────────────────────

log "Installing system dependencies..."
sudo apt-get update -q
sudo apt-get install -y \
  build-essential gcc cmake \
  python3-full python3-dev python3-pip \
  libgmp-dev libgmp3-dev libgmpxx4ldbl \
  libsodium-dev nlohmann-json3-dev \
  nasm m4 curl time libgl1 bc

# ─── 2. Rust (nightly) ───────────────────────────────────────────────────────

if ! command -v rustup &>/dev/null; then
  log "Installing Rust toolchain manager (rustup)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none
else
  skip "rustup"
fi

# shellcheck disable=SC1090
source "$HOME/.cargo/env"

log "Activating Rust nightly..."
rustup install nightly
rustup default nightly
log "Rust: $(rustc --version)"

# ─── 3. Node.js v16 + snarkjs ────────────────────────────────────────────────

export NVM_DIR="$HOME/.nvm"

if [ ! -s "$NVM_DIR/nvm.sh" ]; then
  log "Installing nvm..."
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | bash
fi
# shellcheck disable=SC1090
source "$NVM_DIR/nvm.sh"

if ! node --version 2>/dev/null | grep -q "v16"; then
  log "Installing Node.js v16.20.0..."
  nvm install v16.20.0
  nvm use v16.20.0
else
  skip "Node.js v16"
  nvm use v16.20.0
fi

if ! command -v snarkjs &>/dev/null; then
  log "Installing snarkjs..."
  npm install -g snarkjs
else
  skip "snarkjs"
fi

# ─── 4. Circom ───────────────────────────────────────────────────────────────

if ! command -v circom &>/dev/null; then
  log "Building and installing circom..."
  TMP_CIRCOM="$(mktemp -d)"
  git clone --depth 1 https://github.com/iden3/circom.git "$TMP_CIRCOM/circom"
  pushd "$TMP_CIRCOM/circom" > /dev/null
  # circom's own build requires stable; restore nightly afterwards
  rustup default stable
  cargo build --release
  cargo install --path .
  rustup default nightly
  popd > /dev/null
  rm -rf "$TMP_CIRCOM"
  log "circom: $(circom --version)"
else
  skip "circom ($(circom --version))"
fi

# ─── 5. rapidsnark (needed by VerITAS/VIMz/TilesProof comparisons) ───────────

RAPIDSNARK_BIN="$SCRIPT_DIR/comparisons/rapidsnark/build/proverServer"
if [ ! -f "$RAPIDSNARK_BIN" ]; then
  log "Building rapidsnark..."
  mkdir -p "$SCRIPT_DIR/comparisons"
  pushd "$SCRIPT_DIR/comparisons" > /dev/null
  if [ ! -d "rapidsnark" ]; then
    git clone https://github.com/iden3/rapidsnark.git
  fi
  pushd rapidsnark > /dev/null
  git submodule init
  git submodule update
  ./build_gmp.sh host
  make host
  popd > /dev/null
  popd > /dev/null
else
  skip "rapidsnark"
fi

# ─── 6. Git submodules (hyperplonk + plonkish_basefold) ─────────────────────

log "Initializing git submodules..."
cd "$SCRIPT_DIR"
git submodule update --init --recursive

# ─── 7. Python venv + test image generation ──────────────────────────────────

log "Setting up Python environment..."
cd "$SCRIPT_DIR/hyperveritas_impl"
if [ ! -d "hyperveritas" ]; then
  python3 -m venv hyperveritas
fi
# shellcheck disable=SC1091
source hyperveritas/bin/activate
pip install -q -r images/requirements.txt

log "Generating test images (this writes to hyperveritas_impl/hyperveritas/)..."
cd images
python helper.py
deactivate
cd "$SCRIPT_DIR"

log "Setup complete."
if $SETUP_ONLY; then
  log "Exiting after setup (--setup mode)."
  exit 0
fi

# ─── 8. Build ────────────────────────────────────────────────────────────────

log "Building HyperVerITAS in release mode (first build takes 10-30 min)..."
cd "$SCRIPT_DIR/hyperveritas_impl"
cargo build --release 2>&1 | tee -a "$LOG_DIR/build.log"
log "Build finished."

# ─── 9. Benchmarks ───────────────────────────────────────────────────────────

if $QUICK; then
  SIZES=(19 20 21)
  log "Quick mode: sizes ${SIZES[*]}"
else
  SIZES=(19 20 21 22 23 24 25)
  log "Full mode: sizes ${SIZES[*]}"
fi

run_bench() {
  local example="$1" size="$2"
  local outfile="$LOG_DIR/${example}_${size}.txt"
  log "  ${example} size=${size}"
  # Capture both stdout and /usr/bin/time stderr into the same file
  { /usr/bin/time -v cargo run --release --example "$example" "$size"; } \
    > "$outfile" 2>&1 \
    || log "  WARN: ${example} size=${size} exited non-zero (possible OOM at large sizes)"
}

# Paper Experiment 1 / Table 3: Full System Crop
# (HyperVerITAS Brakedown and PST are the headline numbers)
log "=== Experiment 1 — Full System Crop (Table 3) ==="
for sz in "${SIZES[@]}"; do
  run_bench hv_crop_brakedown "$sz"
  run_bench hv_crop_pst       "$sz"
done

# Paper Experiment 3 / Table 7: Full System Grayscale
log "=== Experiment 3 — Full System Grayscale (Table 7) ==="
for sz in "${SIZES[@]}"; do
  run_bench hv_gray_brakedown "$sz"
  run_bench hv_gray_pst       "$sz"
done

if ! $QUICK; then
  # Paper Experiment 2 / Figure 7: HyperVerITAS vs VerITAS — all PCS variants
  log "=== Experiment 2 — HyperVerITAS PCS sweep (Figure 7, crop) ==="
  for sz in "${SIZES[@]}"; do
    run_bench hv_crop_brakedown_64  "$sz"
    run_bench hv_crop_brakedown_256 "$sz"
    run_bench hv_crop_basefold      "$sz"
    run_bench hv_crop_basefold_fri  "$sz"
    run_bench hv_crop_zeromorph     "$sz"
  done
fi

# ─── 10. Summary ─────────────────────────────────────────────────────────────

log "=== Results summary ==="
printf "%-38s  %-28s  %-28s  %-22s  %s\n" \
  "Run" "Prover Runtime" "Verifier Runtime" "Proof Size" "Peak Mem (kB)" \
  | tee -a "$LOG_DIR/summary.txt"
printf "%-38s  %-28s  %-28s  %-22s  %s\n" \
  "---" "--------------" "----------------" "----------" "-------------" \
  | tee -a "$LOG_DIR/summary.txt"

for f in "$LOG_DIR"/*.txt; do
  name=$(basename "$f" .txt)
  prover=$(grep -m1 "Prover Runtime"          "$f" 2>/dev/null || true)
  verifier=$(grep -m1 "Verifier Runtime"       "$f" 2>/dev/null || true)
  proof=$(grep -m1 "Proof Size"               "$f" 2>/dev/null || true)
  mem=$(grep "Maximum resident set size"       "$f" 2>/dev/null | awk '{print $NF}' || true)
  printf "%-38s  %-28s  %-28s  %-22s  %s\n" \
    "$name" "${prover:-N/A}" "${verifier:-N/A}" "${proof:-N/A}" "${mem:-N/A}" \
    | tee -a "$LOG_DIR/summary.txt"
done

log "Done. Results saved to $LOG_DIR/"
log "  summary.txt — parsed metrics table"
log "  *.txt       — raw output per benchmark"
