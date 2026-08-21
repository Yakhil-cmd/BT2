# Q115: rpc decode panic in lib::status_handler

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling malformed JSON, oversized fields and unexpected types, drive `chain/jsonrpc/src/lib.rs::status_handler` to panic the RPC handler with a crafted request, breaking the invariant that every malformed request produces a typed error response, and leading to RPC node crash or unavailability?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `status_handler`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: malformed JSON, oversized fields and unexpected types
- Exploit idea: panic the RPC handler with a crafted request
- Invariant to test: every malformed request produces a typed error response
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
