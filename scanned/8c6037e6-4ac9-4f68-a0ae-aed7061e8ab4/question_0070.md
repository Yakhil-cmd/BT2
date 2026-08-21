# Q70: query height confusion in lib::light_client_block_proof

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling block ids and finality settings pointing at different heights, drive `chain/jsonrpc/src/lib.rs::light_client_block_proof` to have the response mix data from different heights, breaking the invariant that every response is consistent with exactly one block, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `light_client_block_proof`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: block ids and finality settings pointing at different heights
- Exploit idea: have the response mix data from different heights
- Invariant to test: every response is consistent with exactly one block
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
