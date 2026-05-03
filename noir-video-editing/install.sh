#!/bin/bash
# install.sh — installs all dependencies for noir-video-editing
# Supports macOS (Homebrew) and Linux (apt)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[ok]${NC}    $1"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $1"; }
info() { echo -e "        $1"; }
fail() { echo -e "${RED}[fail]${NC}  $1"; exit 1; }

# ── OS detection ────────────────────────────────────────────────────────────
OS="$(uname -s)"
if [[ "$OS" == "Darwin" ]]; then
    PKG_MGR="brew"
elif [[ "$OS" == "Linux" ]]; then
    PKG_MGR="apt"
else
    fail "Unsupported OS: $OS"
fi

echo "===== noir-video-editing: dependency installer ====="
echo "OS: $OS  |  Package manager: $PKG_MGR"
echo ""

# ── Homebrew (macOS only) ────────────────────────────────────────────────────
if [[ "$PKG_MGR" == "brew" ]]; then
    if ! command -v brew &>/dev/null; then
        info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
        ok "Homebrew"
    fi
fi

# ── Rust ────────────────────────────────────────────────────────────────────
if command -v cargo &>/dev/null; then
    ok "Rust/cargo ($(cargo --version))"
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    ok "Rust/cargo installed"
fi

# ── Python 3 ────────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    ok "Python3 ($(python3 --version))"
else
    info "Installing Python 3..."
    if [[ "$PKG_MGR" == "brew" ]]; then
        brew install python
    else
        sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip
    fi
    ok "Python3 installed"
fi

# ── pip ─────────────────────────────────────────────────────────────────────
if ! python3 -m pip --version &>/dev/null; then
    info "Installing pip..."
    if [[ "$PKG_MGR" == "brew" ]]; then
        brew install python  # pip ships with Homebrew python
    else
        sudo apt-get install -y python3-pip
    fi
fi

# ── Python packages ─────────────────────────────────────────────────────────
info "Installing Python packages (opencv-python, numpy)..."
python3 -m pip install --quiet opencv-python numpy --break-system-packages \
    || python3 -m pip install --quiet opencv-python numpy
ok "Python packages (opencv-python, numpy)"

# ── Nargo (Noir) ────────────────────────────────────────────────────────────
if command -v nargo &>/dev/null; then
    ok "nargo ($(nargo --version 2>/dev/null | head -1))"
else
    info "Installing nargo via noirup..."
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
    # noirup installs to ~/.nargo/bin; add to PATH for this session
    export PATH="$HOME/.nargo/bin:$PATH"
    if command -v noirup &>/dev/null; then
        noirup
        ok "nargo installed"
    else
        warn "noirup installed but not on PATH — open a new shell and run: noirup"
    fi
fi

# ── Barretenberg (bb) ───────────────────────────────────────────────────────
if command -v bb &>/dev/null; then
    ok "bb (barretenberg)"
else
    info "Installing bb (barretenberg)..."
    if [[ "$PKG_MGR" == "brew" ]]; then
        if ! command -v bbup &>/dev/null; then
            curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
            export PATH="$HOME/.bb:$PATH"
        fi
        if command -v bbup &>/dev/null; then
            bbup
            ok "bb installed"
        else
            warn "bbup installed but not on PATH — open a new shell and run: bbup"
        fi
    else
        # Linux: build from source or use the pre-built binary
        BB_VERSION="0.82.2"
        BB_URL="https://github.com/AztecProtocol/aztec-packages/releases/download/aztec-packages-v${BB_VERSION}/barretenberg-x86_64-linux-gnu.tar.gz"
        info "Downloading bb binary for Linux (v${BB_VERSION})..."
        mkdir -p "$HOME/.bb"
        curl -L "$BB_URL" | tar -xz -C "$HOME/.bb"
        chmod +x "$HOME/.bb/bb"
        export PATH="$HOME/.bb:$PATH"
        ok "bb installed to ~/.bb/bb"
        warn "Add ~/.bb to your PATH: export PATH=\"\$HOME/.bb:\$PATH\""
    fi
fi

# ── CRS file ────────────────────────────────────────────────────────────────
CRS_DIR="$HOME/.bb-crs"
CRS_FILE="$CRS_DIR/bn254_g1.dat"
if [[ -f "$CRS_FILE" ]]; then
    SIZE=$(du -sh "$CRS_FILE" | cut -f1)
    ok "CRS file (~/.bb-crs/bn254_g1.dat, $SIZE)"
else
    info "Downloading BN254 CRS file (~1 GB) to ~/.bb-crs ..."
    mkdir -p "$CRS_DIR"
    if command -v bb &>/dev/null; then
        # Let bb download it on first use by running a dummy command
        bb write_vk --help &>/dev/null || true
    fi
    if [[ ! -f "$CRS_FILE" ]]; then
        warn "CRS file not yet downloaded. It will be fetched automatically on first proof run."
        warn "To pre-download: run any 'bb prove' or 'bb write_vk' command."
    else
        ok "CRS file downloaded"
    fi
fi

# ── Compile Rust crate ──────────────────────────────────────────────────────
info "Building generate_freivalds_inputs (release)..."
cd "$SCRIPT_DIR/generate_freivalds_inputs"
RUSTFLAGS="-A warnings" cargo build --release -q
ok "generate_freivalds_inputs compiled"
cd "$SCRIPT_DIR"

# ── Compile Noir circuits ────────────────────────────────────────────────────
info "Compiling Noir circuits..."
for circuit in video_blurring non_keyframe_edits; do
    if [[ -d "$SCRIPT_DIR/$circuit" ]]; then
        cd "$SCRIPT_DIR/$circuit"
        if nargo compile -q 2>/dev/null; then
            ok "Noir circuit: $circuit"
        else
            warn "nargo compile failed for $circuit — check nargo is on PATH"
        fi
        cd "$SCRIPT_DIR"
    fi
done

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "===== All dependencies installed ====="
echo ""
echo "To verify everything is working, run:"
echo "  nargo --version"
echo "  bb --version"
echo "  cargo --version"
echo "  python3 -c 'import cv2, numpy; print(\"ok\")'"
echo ""
echo "To run the pipeline:"
echo "  ./run_e2e.sh 20    # prove first 20 frames"
