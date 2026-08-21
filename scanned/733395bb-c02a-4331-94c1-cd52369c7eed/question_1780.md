# Q1780: viewer panic in mod::prefix_successor

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling account ids, keys and prefixes at their boundaries, drive `runtime/runtime/src/state_viewer/mod.rs::prefix_successor` to panic the state viewer from an unauthenticated query, breaking the invariant that the state viewer never panics on attacker input, and leading to RPC node crash or unavailability?

## Target
- File/function: `runtime/runtime/src/state_viewer/mod.rs` -> `prefix_successor`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: account ids, keys and prefixes at their boundaries
- Exploit idea: panic the state viewer from an unauthenticated query
- Invariant to test: the state viewer never panics on attacker input
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
