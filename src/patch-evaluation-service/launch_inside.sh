#!/usr/bin/env bash
set -euo pipefail

# Config inside the wrapper
ARVO_IMAGE="${ARVO_IMAGE:-n132/arvo:42528804-vul}"
ARVO_NAME="${ARVO_NAME:-arvo_run}"
ARVO_CMD="${ARVO_CMD:-arvo}"
HOST_SHARED="${HOST_SHARED:-/app/ap_shared}"    # this is the path inside the wrapper
LOG_FILE="${LOG_FILE:-${HOST_SHARED}/arvo_output.log}"
KEEP_ALIVE="${KEEP_ALIVE:-true}"                # "false" -> wrapper exits when ARVO exits

mkdir -p "$HOST_SHARED"

# Start ARVO detached; auto-remove when it exits
docker run -d --rm --name "$ARVO_NAME" \
  -v "${HOST_SHARED}:/shared" \
  -e HOST_SHARED="/shared" \
  "$ARVO_IMAGE" $ARVO_CMD

# Stream logs to the shared file (host can read it)
( docker logs -f "$ARVO_NAME" >"$LOG_FILE" 2>&1 ) &
LOGGER_PID=$!

# If wrapper gets stopped, also stop ARVO and the logger
trap 'docker stop -t 10 "$ARVO_NAME" >/dev/null 2>&1 || true; kill "$LOGGER_PID" >/dev/null 2>&1 || true' TERM INT

# Wait for ARVO to finish
STATUS=0
docker wait "$ARVO_NAME" >/dev/null || STATUS=$?

# Stop logger
kill "$LOGGER_PID" >/dev/null 2>&1 || true

if [ "$KEEP_ALIVE" = "true" ]; then
  # Keep wrapper alive so you can docker exec later if you want
  tail -f /dev/null
else
  exit "$STATUS"
fi
