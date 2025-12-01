#!/bin/bash
set -euo pipefail

IMAGE_NAME=spip-go-e2e

# Build image
docker build -t "$IMAGE_NAME" -f Dockerfile .

# Run tests inside container (container runs as root so the test script's root check passes).
# We add NET_ADMIN and NET_RAW so the container can manipulate iptables inside its own namespace.
docker run --rm -it \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v "$(pwd)":/work -w /work \
  "$IMAGE_NAME" bash -lc "scripts/run_e2e_tests.sh"
