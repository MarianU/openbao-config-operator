#!/usr/bin/env bash
set -euo pipefail
envsubst < "$1" | kubectl apply -f -