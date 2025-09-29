#!/usr/bin/env bash
set -euo pipefail

WRAPPER_IMAGE="${WRAPPER_IMAGE:-docker_arvo}"
WRAPPER_NAME="${WRAPPER_NAME:-wrapper_run3}"
HOST_SHARED="${HOST_SHARED:-$(pwd)/ap_shared_host}"

mkdir -p "$HOST_SHARED"

# Run wrapper detached, with:
#  - host docker.sock (so wrapper can launch ARVO)
#  - shared dir bind (to capture logs)
#  - launch_inside.sh bind-mounted and executed as the entrypoint command
docker run -d --name "$WRAPPER_NAME" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOST_SHARED:/app/ap_shared" \
  -v "$(pwd)/launch_inside.sh:/launch_inside.sh:ro" \
  -e HOST_SHARED="/app/ap_shared" \
  "$WRAPPER_IMAGE" \
  bash -lc "/launch_inside.sh"

echo "Wrapper is up: $WRAPPER_NAME"
echo "Logs will stream to: $HOST_SHARED/arvo_output.log"
