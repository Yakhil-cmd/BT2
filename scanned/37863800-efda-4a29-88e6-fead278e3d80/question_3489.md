# Q3489: viewer memory blowup in mod::view_global_contract_code

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling queries over attacker-populated key ranges, drive `runtime/runtime/src/state_viewer/mod.rs::view_global_contract_code` to force unbounded memory use in a view query, breaking the invariant that view query memory is bounded per request, and leading to RPC node crash or unavailability?

## Target
- File/function: `runtime/runtime/src/state_viewer/mod.rs` -> `view_global_contract_code`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: queries over attacker-populated key ranges
- Exploit idea: force unbounded memory use in a view query
- Invariant to test: view query memory is bounded per request
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
