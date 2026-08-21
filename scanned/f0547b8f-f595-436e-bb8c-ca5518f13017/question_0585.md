# Q585: stale chunk view in flat_store::set

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling queries aimed at a block boundary while deltas are applied, drive `core/store/src/adapter/flat_store.rs::set` to read state from a view that mixes two block heights, breaking the invariant that a chunk view exposes exactly one consistent state snapshot, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/store/src/adapter/flat_store.rs` -> `set`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: queries aimed at a block boundary while deltas are applied
- Exploit idea: read state from a view that mixes two block heights
- Invariant to test: a chunk view exposes exactly one consistent state snapshot
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
