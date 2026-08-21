# Q3480: view/execution divergence in mod::call_function

## Question
Can an unprivileged attacker who issues unauthenticated JSON-RPC queries against a public node, controlling a contract whose view result differs from its executed result, drive `runtime/runtime/src/state_viewer/mod.rs::call_function` to have the view path report state that execution would not produce, breaking the invariant that view execution matches transactional execution for read-only calls, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/state_viewer/mod.rs` -> `call_function`
- Entrypoint: unprivileged attacker issues unauthenticated JSON-RPC queries against a public node
- Attacker controls: a contract whose view result differs from its executed result
- Exploit idea: have the view path report state that execution would not produce
- Invariant to test: view execution matches transactional execution for read-only calls
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
