# Q3805: table growth cost in instrument_v3::call_gas_instrumentation

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling table declarations and grow operations at the limits, drive `runtime/near-vm-runner/src/prepare/instrument_v3.rs::call_gas_instrumentation` to grow tables without paying the corresponding gas, breaking the invariant that every table growth is charged before it happens, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/instrument_v3.rs` -> `call_gas_instrumentation`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: table declarations and grow operations at the limits
- Exploit idea: grow tables without paying the corresponding gas
- Invariant to test: every table growth is charged before it happens
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
