# Q1924: unbounded query cost in lib::tx_exists

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling query ranges, prefixes and depths at their maxima, drive `chain/jsonrpc/src/lib.rs::tx_exists` to make a single unauthenticated query consume unbounded node CPU or memory, breaking the invariant that every RPC query has a bounded, enforced cost, and leading to RPC node crash or unavailability?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `tx_exists`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: query ranges, prefixes and depths at their maxima
- Exploit idea: make a single unauthenticated query consume unbounded node CPU or memory
- Invariant to test: every RPC query has a bounded, enforced cost
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
