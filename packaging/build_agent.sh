#!/usr/bin/env bash
# Build the APT Simulator agent into a single Linux/macOS executable.
# Usage:
#   ./packaging/build_agent.sh
#
# Output: dist/apt-agent
# Notes:
#   - Run from the project root.
#   - The venv must already have dev dependencies installed: pip install -e ".[dev]"

set -euo pipefail

if [[ ! -x ".venv/bin/pyinstaller" ]]; then
    echo "PyInstaller not found in .venv. Run: pip install -e '.[dev]'" >&2
    exit 1
fi

echo "Building agent binary..."
.venv/bin/pyinstaller packaging/agent.spec --clean --noconfirm

if [[ -f "dist/apt-agent" ]]; then
    size=$(du -h dist/apt-agent | cut -f1)
    echo "Build succeeded: dist/apt-agent (${size})"
else
    echo "Expected output dist/apt-agent not found" >&2
    exit 1
fi
