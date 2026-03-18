#!/usr/bin/env bash
# Adversarial test runner for capsec.
# Creates a timestamped run directory with test output and metadata.
set -euo pipefail

DOCS_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$DOCS_DIR/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"

echo "=== capsec adversarial test run ==="
echo "Output: $RUN_DIR"

# Capture metadata
{
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "rust: $(rustc --version)"
    echo "cargo: $(cargo --version)"
    echo "os: $(uname -srm)"
    echo "git_sha: $(git -C "$DOCS_DIR/../../../" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
} > "$RUN_DIR/metadata.txt"

# Run tests and capture output
echo "Running tests..."
cargo test -p capsec-tests -- --show-output 2>&1 | tee "$RUN_DIR/test-output.txt"
EXIT_CODE=${PIPESTATUS[0]}

# Run clippy
echo ""
echo "Running clippy..."
cargo clippy -p capsec-tests --tests -- -D warnings 2>&1 | tee "$RUN_DIR/clippy-output.txt"

echo ""
echo "=== Test run complete ==="
echo "Exit code: $EXIT_CODE"
echo "Results saved to: $RUN_DIR"

exit $EXIT_CODE
