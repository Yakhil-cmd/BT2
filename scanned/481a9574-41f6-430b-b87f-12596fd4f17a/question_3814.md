# Q3814: stack height bypass in instrument_v3::run

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling deep recursion and large local frames just under the stack limit, drive `runtime/near-vm-runner/src/prepare/instrument_v3.rs::run` to exceed the enforced stack limit and reach a host stack overflow, breaking the invariant that wasm stack usage never exceeds the configured limit, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/instrument_v3.rs` -> `run`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: deep recursion and large local frames just under the stack limit
- Exploit idea: exceed the enforced stack limit and reach a host stack overflow
- Invariant to test: wasm stack usage never exceeds the configured limit
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
