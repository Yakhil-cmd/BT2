# Q109: sandbox path exposure in lib::shard_layout_for_epoch

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling requests aimed at sandbox-only endpoints, drive `chain/jsonrpc/src/lib.rs::shard_layout_for_epoch` to reach a sandbox-only mutation endpoint on a production node, breaking the invariant that sandbox endpoints are absent from production builds, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `shard_layout_for_epoch`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: requests aimed at sandbox-only endpoints
- Exploit idea: reach a sandbox-only mutation endpoint on a production node
- Invariant to test: sandbox endpoints are absent from production builds
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
