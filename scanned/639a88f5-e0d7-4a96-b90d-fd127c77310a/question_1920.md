# Q1920: state query size limit in lib::status_handler

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling a prefix matching an attacker-populated key space, drive `chain/jsonrpc/src/lib.rs::status_handler` to force the node to serialize an unbounded state response, breaking the invariant that state responses are bounded by the configured limits, and leading to RPC node crash or unavailability?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `status_handler`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: a prefix matching an attacker-populated key space
- Exploit idea: force the node to serialize an unbounded state response
- Invariant to test: state responses are bounded by the configured limits
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
