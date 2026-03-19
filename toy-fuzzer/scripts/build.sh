#!/usr/bin/env bash
# build.sh — compile all 4 fuzzer binaries from toy-fuzzer/.
# Run from the toy-fuzzer/ directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "=== Building all fuzzer configurations ==="
make clean
make all 2>&1 | tee results/build.log

echo ""
echo "=== Build complete. Binaries:"
ls -lh bin/
