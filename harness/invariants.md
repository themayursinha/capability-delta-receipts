# Capability Delta Receipts — Invariants

## CD-1 — In-scope accumulation never pauses solely because risk is high

A step whose effect target lies inside the declared envelope is always
`ALLOW`, even when the delta confirms memory-corruption or sandbox-escape
primitives. Risk alone is not a pause trigger; only a boundary-crossing
effect target is.

## CD-2 — Boundary-crossing effects never execute before a durable pause receipt

A step whose effect target lies outside the declared envelope emits a
`PAUSE_REQUIRE_NEW_PROOF` receipt before the effect can execute. On the
guarded path no boundary effect occurs and the out-of-envelope canary stays
untouched.

## CD-3 — Every claimed capability delta cites at least one observed signal

A confirmed capability delta requires at least one non-declared signal at
`artifact`, `runtime_marker`, or `boundary_request` evidence level. Declared
intent alone yields a `provisional` capability with evidence level
`declared_only` and never a confirmed delta.

## CD-4 — The control can affect only an ephemeral outer-container canary

The unguarded counterfactual control may reach only the ephemeral disposable
container canary; the workstation host and real network remain unreachable.

## CD-5 — Authority Graph Simulator integration is a future adapter task

This slice is standalone. Adapter work against Authority Graph Simulator or
any MCP proxy is out of scope.

## CD-6 — Receipts are canonical, deterministic, hash-linked JSONL

Each step emits one JSON object per line with deterministic field ordering.
`prev_hash` links to the previous line's `hash`; `hash` is the SHA-256 over
the canonical JSON of the current line. Identical trajectories in different
input orders produce byte-identical encoded receipts.
