#!/bin/bash

# Shared logging helpers for tests.
# Source from a test script: source "$SCRIPT_DIR/lib/log.sh"

info() { echo "INFO: $*"; }
err()  { echo "ERROR: $*" >&2; }
