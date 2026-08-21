# Q1927: changes endpoint blowup in lib::tx_status_fetch_single

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling block ranges and filters selected to maximise scanned data, drive `chain/jsonrpc/src/lib.rs::tx_status_fetch_single` to make a changes query scan far more than the request implies, breaking the invariant that changes queries are bounded by the requested range, and leading to RPC node crash or unavailability?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `tx_status_fetch_single`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: block ranges and filters selected to maximise scanned data
- Exploit idea: make a changes query scan far more than the request implies
- Invariant to test: changes queries are bounded by the requested range
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
