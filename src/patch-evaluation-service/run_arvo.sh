#!/usr/bin/env bash
set -euo pipefail
: "${ARVO_IMAGE:=docker_arvo:latest}"
: "${HOST_SHARED:=/app/ap_shared}"

mkdir -p "$HOST_SHARED"

exec docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${HOST_SHARED}:/shared" \
  -e HOST_SHARED="${HOST_SHARED}" \
  "$ARVO_IMAGE" "$@"
