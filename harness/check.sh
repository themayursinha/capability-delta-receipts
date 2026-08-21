#!/usr/bin/env bash
# Capability Delta Receipts harness gate.
#
# Runs format check, vet, unit/CLI tests, race tests, and all five golden
# fixture comparisons, then writes a gitignored evidence manifest under
# evidence/harness/<UTC timestamp>/manifest.md.
set -uo pipefail

cd "$(dirname "$0")/.."
export PATH="/usr/local/go/bin:$PATH"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="evidence/harness/${STAMP}"
mkdir -p "${EVIDENCE_DIR}"
MANIFEST="${EVIDENCE_DIR}/manifest.md"

FAILURES=0

record() {
  local name="$1"
  shift
  echo "### ${name}" >> "${MANIFEST}"
  echo '```' >> "${MANIFEST}"
  if "$@" >> "${MANIFEST}" 2>&1; then
    echo '```' >> "${MANIFEST}"
    echo "PASS: ${name}" >> "${MANIFEST}"
  else
    echo '```' >> "${MANIFEST}"
    echo "FAIL: ${name}" >> "${MANIFEST}"
    FAILURES=$((FAILURES + 1))
  fi
}

{
  echo "# Capability Delta Receipts harness"
  echo
  echo "Timestamp: $(date -u -Is)"
  echo "Go: $(go version)"
  echo
} > "${MANIFEST}"

record "gofmt" bash -c 'test "$(gofmt -l . | wc -l)" -eq 0'
record "go vet ./..." go vet ./...
record "go test ./... -count=1" go test ./... -count=1
record "go test -race ./... -count=1" go test -race ./... -count=1
record "fixture allow-bug-a" bash -c 'go run ./cmd/capdelta testdata/allow-bug-a.json > /tmp/cap-a.json && diff -u testdata/allow-bug-a.expected.json /tmp/cap-a.json'
record "fixture allow-bug-b" bash -c 'go run ./cmd/capdelta testdata/allow-bug-b.json > /tmp/cap-b.json && diff -u testdata/allow-bug-b.expected.json /tmp/cap-b.json'
record "fixture pause-composition" bash -c 'go run ./cmd/capdelta testdata/pause-composition.json > /tmp/cap-pc.json && diff -u testdata/pause-composition.expected.json /tmp/cap-pc.json'
record "fixture pause-egress" bash -c 'go run ./cmd/capdelta testdata/pause-egress.json > /tmp/cap-pe.json && diff -u testdata/pause-egress.expected.json /tmp/cap-pe.json'
record "fixture allow-full-research" bash -c 'go run ./cmd/capdelta testdata/allow-full-research.json > /tmp/cap-fr.json && diff -u testdata/allow-full-research.expected.json /tmp/cap-fr.json'

echo >> "${MANIFEST}"
if [ "${FAILURES}" -eq 0 ]; then
  echo "RESULT: PASS" >> "${MANIFEST}"
  echo "RESULT: PASS"
  exit 0
else
  echo "RESULT: FAIL (${FAILURES} command(s) failed)" >> "${MANIFEST}"
  echo "RESULT: FAIL (${FAILURES} command(s) failed)" >&2
  exit 1
fi
