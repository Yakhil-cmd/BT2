# Q1777: view gas accounting in mod::call_function

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling view calls that maximise host work per view-gas unit, drive `runtime/runtime/src/state_viewer/mod.rs::call_function` to exceed the view gas budget on a public node, breaking the invariant that view execution is bounded by the view gas limit, and leading to RPC node crash or unavailability?

## Target
- File/function: `runtime/runtime/src/state_viewer/mod.rs` -> `call_function`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: view calls that maximise host work per view-gas unit
- Exploit idea: exceed the view gas budget on a public node
- Invariant to test: view execution is bounded by the view gas limit
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
