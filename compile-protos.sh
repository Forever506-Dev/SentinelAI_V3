#!/usr/bin/env bash
# ============================================================
# SentinelAI — Proto Compilation Script
# ============================================================
# Compiles .proto files into Python and (optionally) Rust bindings.
# Can use either `buf` (preferred) or raw `protoc`.
#
# Usage:
#   ./scripts/compile-protos.sh           # Compile all
#   ./scripts/compile-protos.sh --check   # Validate only (CI)
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

CHECK_ONLY=false
if [[ "${1:-}" == "--check" ]]; then
    CHECK_ONLY=true
fi

# ── Colors ───────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

# ── Output directories ──────────────────────────────────────
PYTHON_OUT="gen/python"
RUST_OUT="gen/rust"

mkdir -p "$PYTHON_OUT" "$RUST_OUT"

# ── Method 1: Use buf (preferred) ───────────────────────────
if command -v buf &>/dev/null; then
    echo "Using buf for proto compilation..."

    if [ "$CHECK_ONLY" = true ]; then
        echo "Linting proto files..."
        buf lint && ok "Proto lint passed" || { err "Proto lint failed"; exit 1; }

        echo "Validating proto compilation..."
        buf build && ok "Proto compilation valid" || { err "Proto compilation failed"; exit 1; }
        exit 0
    fi

    buf generate
    ok "Proto files compiled via buf → $PYTHON_OUT"
    exit 0
fi

# ── Method 2: Fallback to protoc ────────────────────────────
if ! command -v protoc &>/dev/null; then
    err "Neither 'buf' nor 'protoc' found."
    warn "Install buf:    https://buf.build/docs/installation"
    warn "Install protoc: apt install protobuf-compiler  (or brew install protobuf)"
    exit 1
fi

echo "Using protoc for proto compilation..."

# Install Python gRPC tools if needed
if ! python -c "import grpc_tools" 2>/dev/null; then
    warn "Installing grpcio-tools..."
    pip install grpcio-tools
fi

# ── Compile v1 proto ─────────────────────────────────────────
V1_PROTO="shared/proto/sentinel.proto"
if [ -f "$V1_PROTO" ]; then
    if [ "$CHECK_ONLY" = true ]; then
        protoc --proto_path=shared/proto --python_out=/tmp "$V1_PROTO"
        ok "sentinel.proto (v1) compiles"
    else
        python -m grpc_tools.protoc \
            --proto_path=shared/proto \
            --python_out="$PYTHON_OUT" \
            --grpc_python_out="$PYTHON_OUT" \
            --pyi_out="$PYTHON_OUT" \
            "$V1_PROTO"
        ok "sentinel.proto (v1) → $PYTHON_OUT"
    fi
fi

# ── Compile v2 proto ─────────────────────────────────────────
V2_PROTO="docs/architecture/proto/sentinel_v2.proto"
if [ -f "$V2_PROTO" ]; then
    if [ "$CHECK_ONLY" = true ]; then
        protoc --proto_path=docs/architecture/proto --python_out=/tmp "$V2_PROTO"
        ok "sentinel_v2.proto (v2) compiles"
    else
        python -m grpc_tools.protoc \
            --proto_path=docs/architecture/proto \
            --python_out="$PYTHON_OUT" \
            --grpc_python_out="$PYTHON_OUT" \
            --pyi_out="$PYTHON_OUT" \
            "$V2_PROTO"
        ok "sentinel_v2.proto (v2) → $PYTHON_OUT"
    fi
fi

# ── Create __init__.py for Python package ────────────────────
if [ "$CHECK_ONLY" = false ]; then
    touch "$PYTHON_OUT/__init__.py"
    ok "Generated Python proto package at $PYTHON_OUT"
fi

echo ""
ok "Proto compilation complete."
