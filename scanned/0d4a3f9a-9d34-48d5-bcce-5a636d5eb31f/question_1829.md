# Q1829: view state proof cost in lib::adv_disable_header_sync

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling proof requests over deep attacker-built subtrees, drive `chain/jsonrpc/src/lib.rs::adv_disable_header_sync` to force expensive proof generation for free, breaking the invariant that proof generation cost is bounded per request, and leading to RPC node crash or unavailability?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `adv_disable_header_sync`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: proof requests over deep attacker-built subtrees
- Exploit idea: force expensive proof generation for free
- Invariant to test: proof generation cost is bounded per request
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
