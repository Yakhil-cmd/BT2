# Q1914: error message disclosure in lib::shard_layout_for_epoch

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling requests crafted to trigger verbose internal errors, drive `chain/jsonrpc/src/lib.rs::shard_layout_for_epoch` to learn internal node state or paths from an error response, breaking the invariant that errors never disclose internal node internals, and leading to griefing / validator resource exhaustion with no direct profit?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `shard_layout_for_epoch`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: requests crafted to trigger verbose internal errors
- Exploit idea: learn internal node state or paths from an error response
- Invariant to test: errors never disclose internal node internals
- Expected Immunefi impact: Medium - griefing / validator resource exhaustion with no direct profit
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
