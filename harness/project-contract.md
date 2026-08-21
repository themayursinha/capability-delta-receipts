# Capability Delta Receipts — Project Contract

A standalone, deterministic Go prototype that reduces a scripted agent
trajectory (declared intent + observable events) into provenance-carrying
capability deltas, evaluates each step against a declared target/network
envelope, and emits canonical hash-linked JSONL receipts before any
boundary-crossing execution.

## Boundary

- One trajectory per run, evaluated step by step in order.
- Standard library only. No network access, server, database, UI, policy
  language, telemetry, or third-party Go dependencies.
- Not production capability detection. Not integrated into any MCP proxy or
  authority product. The detector is a declared+detected hybrid with explicit
  evidence levels; it makes no claim of evasion-proof or complete real-world
  detection.
- No real exploits, no real V8 bugs, no host escape, no real network egress.
  All demo bugs are simulated. The container theater (optional) is a
  simulation and is never required by the gate.

## Declared model

- A trajectory is an ordered list of events; each event is one of
  `declare`, `file`, `build`, `runtime`, `request`.
- Signals are typed observations extracted from events, each carrying
  `kind`, `observation`, `evidence_level`, and `source_digest`.
- Evidence levels are ordered `declared_only < artifact < runtime_marker <
  boundary_request`. Declared intent alone yields provisional capability and
  never a confirmed delta.
- Capabilities live in a fixed lattice; only `HOST_EXEC` and `NET_EGRESS`
  lie outside the envelope.
- The envelope is the declared boundary: `declared_target` (the V8-like
  sandbox process inside the container), `declared_network` (none), and
  `declared_host` (unreachable).

## Enforced property

```text
BoundaryPredicate(step):
  effect_target(step) ∈ envelope  →  ALLOW            (record delta receipt)
  effect_target(step) ∉ envelope  →  PAUSE_REQUIRE_NEW_PROOF
                                     (durable receipt BEFORE execution)
```

Only the deterministic boundary predicate decides PAUSE. Heuristics supply
evidence for deltas; they never decide a pause.

## CLI contract

- One positional argument: path to a single JSON trajectory file.
- Strict JSON decoding: unknown fields, duplicate keys, null required
  fields, and trailing JSON are rejected as process errors (non-zero exit,
  no receipt on stdout).
- ALLOW and PAUSE are both authorization results, not process failures
  (exit 0).
- Exit non-zero only for usage errors, unreadable/malformed trajectory
  input, or encoding failures, with no partial receipt on stdout.
- Output is one canonical JSON receipt per trajectory step, in order,
  hash-linked, with deterministic field ordering.
