# Q63: access key listing cost in lib::get_cors

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling an account holding a very large number of keys, drive `chain/jsonrpc/src/lib.rs::get_cors` to turn one query into an unbounded iteration, breaking the invariant that listing endpoints paginate and bound their work, and leading to RPC node crash or unavailability?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `get_cors`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: an account holding a very large number of keys
- Exploit idea: turn one query into an unbounded iteration
- Invariant to test: listing endpoints paginate and bound their work
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
