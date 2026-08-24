#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GOCACHE=/tmp/gocache GO111MODULE=off GOPATH=/tmp/gopath

# --- Step 1: rebuild the authoritative rule base (#NET-9170, #NET-9174) -----
# The configuration migration left /app/data/policy_rules.json holding a
# truncated prefix. Replay the configuration journal onto the pre-migration
# snapshot, resolve every object group transitively, and write the result back
# to that path.

go run "${SCRIPT_DIR}/resolve_rules.go"

# --- Step 2: restore the compiler and produce the policy artifacts ----------

cp "${SCRIPT_DIR}/compile_policy_fixed.go" /app/workflow/compile_policy.go
go run /app/workflow/compile_policy.go --output-dir /app/output
