# Q130: view-call gas bypass in lib::view_account_local

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling a `call_function` view request against attacker-deployed code, drive `chain/jsonrpc/src/lib.rs::view_account_local` to run contract code on a public node beyond the view gas limit, breaking the invariant that view calls are capped by the view gas limit and cannot mutate state, and leading to RPC node crash or unavailability?

## Target
- File/function: `chain/jsonrpc/src/lib.rs` -> `view_account_local`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: a `call_function` view request against attacker-deployed code
- Exploit idea: run contract code on a public node beyond the view gas limit
- Invariant to test: view calls are capped by the view gas limit and cannot mutate state
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
