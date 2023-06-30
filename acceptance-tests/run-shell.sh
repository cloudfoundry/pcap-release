#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Build acceptance test image
pushd "$SCRIPT_DIR/../ci" || exit 1
 docker build -t pcap-release-testflight .
popd || exit 1

# Run local shell
docker run -it --rm --privileged -v "$REPO_DIR":/repo -e REPO_ROOT=/repo pcap-release-testflight bash -c "cd /repo/ci/scripts && ./shell"
