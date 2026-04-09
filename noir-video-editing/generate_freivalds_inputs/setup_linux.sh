#!/bin/bash
# Setup script for running loop_frames_pipelined_*.sh on Linux (Ubuntu/Debian).
# Run once on a fresh machine before running any proving scripts.
#
# Installs:
#   - System build tools + numactl
#   - Rust 1.94+ (via rustup)
#   - Nargo 1.0.0-beta.15 (Noir compiler/executor)
#   - bb 3.0.0-nightly.20251104 (Barretenberg prover)
#   - Downloads the bn254 CRS (~7 GB) to ~/.bb-crs/
#   - Builds the Rust generate_freivalds_inputs binary
#   - Compiles the Noir video_blurring circuit

set -e  # exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VIDEO_BLURRING_DIR="$SCRIPT_DIR/../video_blurring"

NARGO_VERSION="1.0.0-beta.15"
BB_VERSION="3.0.0-nightly.20251104"

echo "================================================================"
echo " fibonacci video proving — Linux setup"
echo " Workspace: $WORKSPACE_ROOT"
echo "================================================================"
echo ""

# ------------------------------------------------------------------ #
# 1. System packages
# ------------------------------------------------------------------ #
echo "===== [1/6] Installing system packages ====="
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    curl \
    git \
    numactl \
    ca-certificates

echo "   numactl: $(numactl --version 2>&1 | head -1)"

# ------------------------------------------------------------------ #
# 2. Rust
# ------------------------------------------------------------------ #
echo ""
echo "===== [2/6] Installing Rust ====="
if command -v rustc &>/dev/null; then
    echo "   Rust already installed: $(rustc --version)"
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    echo "   Installed Rust"
fi
# Make cargo available in this session regardless of shell config
source "$HOME/.cargo/env" 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
echo "   Rust: $(rustc --version)"

# ------------------------------------------------------------------ #
# 3. Nargo (Noir toolchain)
# ------------------------------------------------------------------ #
echo ""
echo "===== [3/6] Installing Nargo $NARGO_VERSION ====="
export PATH="$HOME/.nargo/bin:$PATH"
if ! command -v noirup &>/dev/null; then
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
fi
noirup --version "$NARGO_VERSION"
echo "   $(nargo --version | head -1)"

# ------------------------------------------------------------------ #
# 4. Barretenberg (bb prover)
# ------------------------------------------------------------------ #
echo ""
echo "===== [4/6] Installing bb $BB_VERSION ====="
export PATH="$HOME/.bb/bin:$PATH"
if ! command -v bbup &>/dev/null; then
    curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
fi
bbup --version "$BB_VERSION"
echo "   bb: $(bb --version)"

# ------------------------------------------------------------------ #
# 5. Download CRS (~7 GB — bn254 trusted setup)
# ------------------------------------------------------------------ #
echo ""
echo "===== [5/6] Downloading CRS to ~/.bb-crs/ ====="
mkdir -p "$HOME/.bb-crs"
if [ -f "$HOME/.bb-crs/bn254_g1.dat" ]; then
    echo "   CRS already present ($(du -sh "$HOME/.bb-crs" | cut -f1))"
else
    echo "   Downloading ~7 GB, this will take a while..."
    # bb downloads the CRS automatically on first use; triggering it explicitly
    # by running a lightweight command that requires the CRS.
    bb get_srs --crs_path "$HOME/.bb-crs" -s 262144
    echo "   CRS downloaded: $(du -sh "$HOME/.bb-crs" | cut -f1)"
fi

# ------------------------------------------------------------------ #
# 6. Build project artifacts
# ------------------------------------------------------------------ #
echo ""
echo "===== [6/6] Building project artifacts ====="

# 6a. Rust binary
echo "   Building Rust binary (generate_freivalds_inputs)..."
cd "$WORKSPACE_ROOT"
RUSTFLAGS="-A warnings" cargo build --release
echo "   Binary: $WORKSPACE_ROOT/target/release/generate_freivalds_inputs"

# 6b. Compile Noir circuit and generate VK
echo "   Compiling Noir circuit (video_blurring)..."
cd "$VIDEO_BLURRING_DIR"
nargo compile --force
echo "   Generating VK..."
bb write_vk \
    -b ./target/video_blurring.json \
    -o ./target \
    -c "$HOME/.bb-crs"
echo "   VK written to $VIDEO_BLURRING_DIR/target/vk"

# ------------------------------------------------------------------ #
# Done
# ------------------------------------------------------------------ #
echo ""
echo "================================================================"
echo " Setup complete! Make the proving scripts executable:"
echo ""
echo "   cd $SCRIPT_DIR"
echo "   chmod +x loop_frames_pipelined_1bb.sh loop_frames_pipelined_4bb.sh"
echo ""
echo " Then run:"
echo "   ./loop_frames_pipelined_1bb.sh 10   # single bb, first 10 frames"
echo "   ./loop_frames_pipelined_4bb.sh 10   # 4 parallel bb, first 10 frames"
echo ""
echo " Check NUMA topology before running the 4bb script:"
echo "   numactl --hardware"
echo "================================================================"
