#!/usr/bin/env bash
# Reproduce VIMz benchmarks from:
# "VIMz: Private Proofs of Image Manipulation using Folding-based zkSNARKs" (PETS 2025)
# DOI: 10.5281/zenodo.12516128
#
# Usage:
#   ./reproduce.sh           # full HD benchmark — all 7 transformations
#   ./reproduce.sh --quick   # grayscale + crop only
#   ./reproduce.sh --setup   # install deps + build only, no benchmarks
#
# Target platform: Ubuntu 22.04+, Rust stable, Circom 2.2.1+
# Disk space: ~10 GB for quick mode; ~40 GB for all circuits

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
skip() { log "SKIP: $* (already installed)"; }

# ─── 1. System dependencies ──────────────────────────────────────────────────

log "Installing system dependencies..."
sudo apt-get update -q
sudo apt-get install -y \
  gcc build-essential \
  nlohmann-json3-dev libgmp3-dev \
  nasm time bc curl

# ─── 2. Rust (stable) ────────────────────────────────────────────────────────

if ! command -v rustup &>/dev/null; then
  log "Installing Rust..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- --default-toolchain none -y
else
  skip "rustup"
fi
# shellcheck disable=SC1090
source "$HOME/.cargo/env"
rustup default stable
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
  # Some misconfigured distros need this mirror fallback
  export NVM_NODEJS_ORG_MIRROR=http://nodejs.org/dist
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
  log "Building and installing circom (takes ~5 min)..."
  TMP="$(mktemp -d)"
  git clone --depth 1 https://github.com/iden3/circom.git "$TMP/circom"
  pushd "$TMP/circom" > /dev/null
  cargo build --release
  cargo install --path .
  popd > /dev/null
  rm -rf "$TMP"
  log "circom: $(circom --version)"
else
  skip "circom ($(circom --version))"
fi

# ─── 5. Build vimz binary ────────────────────────────────────────────────────

log "Building vimz Nova prover..."
cd "$SCRIPT_DIR/nova"
cargo build --release 2>&1 | tee -a "$LOG_DIR/build.log"
cargo install --path . 2>&1 | tee -a "$LOG_DIR/build.log"
log "vimz binary: $(which vimz)"

# ─── 6. Build ZK circuits ────────────────────────────────────────────────────

cd "$SCRIPT_DIR/circuits"

if [ ! -d "node_modules" ]; then
  log "Installing circomlib node modules..."
  npm install
fi

if $QUICK; then
  # crop uses the optimized_crop circuit name
  CIRCUITS=(grayscale_step_HD.circom optimized_crop_step_HD.circom)
  log "Quick mode: building 2 circuits (~30-60 min each)..."
else
  CIRCUITS=(
    grayscale_step_HD.circom
    optimized_crop_step_HD.circom
    contrast_step_HD.circom
    brightness_step_HD.circom
    sharpness_step_HD.circom
    resize_step_HD.circom
    blur_step_HD.circom
  )
  log "Full mode: building 7 HD circuits (~3-7 hrs total)..."
fi

for circuit in "${CIRCUITS[@]}"; do
  if [ -f "${circuit%.circom}_cpp/${circuit%.circom}" ]; then
    skip "circuit ${circuit} (witness generator already built)"
  else
    log "  Building: $circuit"
    ./build_circuits.sh "$circuit" 2>&1 | tee -a "$LOG_DIR/circuits_build.log"
  fi
done

log "Circuit builds complete."

if $SETUP_ONLY; then
  log "Exiting after setup (--setup mode)."
  exit 0
fi

# ─── 7. Decompress 4K JSON samples if needed ─────────────────────────────────

for tar_file in "$SCRIPT_DIR/samples/JSON/4K/"*.tar.xz; do
  json_file="${tar_file%.tar.xz}.json"
  if [ -f "$tar_file" ] && [ ! -f "$json_file" ]; then
    log "Decompressing $(basename "$tar_file")..."
    tar -xf "$tar_file" -C "$(dirname "$json_file")"
  fi
done

# ─── 8. Benchmarks ───────────────────────────────────────────────────────────

# Run a single transformation and save full output (stdout + /usr/bin/time stderr)
run_bench() {
  local resolution="$1" function="$2" circuit_prefix="$3" transformation="$4"
  local outfile="$LOG_DIR/${transformation}_${resolution}.txt"
  log "  Benchmarking: $transformation @ $resolution"
  /usr/bin/time -v vimz \
    --function    "$function" \
    --witnessgenerator "$SCRIPT_DIR/circuits/${circuit_prefix}_cpp/${circuit_prefix}" \
    --output      "$LOG_DIR/${transformation}_${resolution}.json" \
    --input       "$SCRIPT_DIR/samples/JSON/$resolution/transformation_${transformation}.json" \
    --circuit     "$SCRIPT_DIR/circuits/${circuit_prefix}.r1cs" \
    --resolution  "$resolution" \
    > "$outfile" 2>&1 \
    || log "  WARN: $transformation $resolution exited non-zero"
}

log "=== Table 4: Single-transformation HD benchmarks ==="
# crop: function name is 'fixedcrop', circuit prefix is 'optimized_crop_step_HD'
run_bench HD fixedcrop optimized_crop_step_HD crop

if $QUICK; then
  run_bench HD grayscale grayscale_step_HD grayscale
else
  run_bench HD grayscale   grayscale_step_HD   grayscale
  run_bench HD contrast    contrast_step_HD    contrast
  run_bench HD brightness  brightness_step_HD  brightness
  run_bench HD sharpness   sharpness_step_HD   sharpness
  run_bench HD resize      resize_step_HD      resize
  run_bench HD blur        blur_step_HD        blur
fi

# ─── 9. Summary ──────────────────────────────────────────────────────────────

log "=== Results summary ==="
cat <<'HDR' | tee -a "$LOG_DIR/summary.txt"
Transformation   Recursive (s)   Compressed (s)   Total Proving (s)   Verify (s)   Peak Mem (kB)
--------------   -------------   --------------   -----------------   ----------   -------------
HDR

for f in "$LOG_DIR"/*.txt; do
  [[ "$f" == *.json ]] && continue
  name=$(basename "$f" .txt)
  recursive=$(grep -oP '(?<=RecursiveSNARK creation took )[0-9.]+' "$f" 2>/dev/null | tail -1 || true)
  compressed=$(grep -oP '(?<=CompressedSNARK::prove: )[0-9.]+' "$f" 2>/dev/null | tail -1 || true)
  verify=$(grep -oP '(?<=CompressedSNARK::verify: )[0-9.]+' "$f" 2>/dev/null | tail -1 || true)
  mem=$(grep "Maximum resident set size" "$f" 2>/dev/null | awk '{print $NF}' || true)

  total="N/A"
  if [[ -n "$recursive" && -n "$compressed" ]]; then
    total=$(echo "$recursive + $compressed" | bc 2>/dev/null || echo "N/A")
  fi

  printf "%-16s  %-13s   %-14s   %-17s   %-10s   %s\n" \
    "$name" "${recursive:-N/A}" "${compressed:-N/A}" "$total" \
    "${verify:-N/A}" "${mem:-N/A}" \
    | tee -a "$LOG_DIR/summary.txt"
done

log "Done. Results saved to $LOG_DIR/"
log "  summary.txt — parsed metrics table (compare to Table 4 in paper)"
log "  *.txt       — raw output per benchmark run"
log ""
log "Expected HD proving times (from paper, Core i5 laptop):"
log "  crop=187s  grayscale=280s  contrast=479s  brightness=474s"
log "  sharpness=614s  resize=187s  blur=555s"
