# Q1892: view-call state mutation in lib::process_sharded_method_call

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling a view request that reaches a mutating host path, drive `chain/jsonrpc/src/lib.rs::process_sharded_method_call` to mutate node state through a supposedly read-only query, breaking the invariant that view calls never write state, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `process_sharded_method_call`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: a view request that reaches a mutating host path
- Exploit idea: mutate node state through a supposedly read-only query
- Invariant to test: view calls never write state
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
