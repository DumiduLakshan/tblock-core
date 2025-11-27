#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/DumiduLakshan/tblock-core.git"
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

command -v git >/dev/null 2>&1 || { echo "git is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }

git clone "$REPO_URL" "$WORKDIR"
cd "$WORKDIR"
python3 installer.py
