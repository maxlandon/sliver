#!/bin/bash

# Sliver Implant Framework
# Copyright (C) 2019  Bishop Fox
#
# Runs the sandbox-based teamserver/teamclient integration suite against a
# throwaway SLIVER_ROOT_DIR, so it never touches a real ~/.sliver. The env var
# MUST be exported before `go test` starts, because server/db opens the database
# at package-init (before TestMain runs); setting it from inside a test is too
# late. See tests/teamserver/harness_test.go.
#
# Usage:  ./tests/teamserver/run.sh [extra go test args...]
#   e.g.  ./tests/teamserver/run.sh -run TestConnectAndVersion -v

set -euo pipefail

# Match the tag set used by go-tests.sh (pure-Go sqlite, static-friendly).
TAGS="server,osusergo,netgo,go_sqlite"

# Isolated, auto-cleaned sandbox root for this run.
SANDBOX_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sliver-itest.XXXXXX")"
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

echo "==> SLIVER_ROOT_DIR=$SANDBOX_ROOT"
echo "==> tags: $TAGS"

# -race catches the connect/disconnect data races the connection map flagged;
# -timeout bounds the whole run so a missed watchdog still can't hang CI.
SLIVER_ROOT_DIR="$SANDBOX_ROOT" \
	go test -tags="$TAGS" -race -timeout 5m -v "$@" ./tests/teamserver/
