# Q3818: export/start abuse in prepare_v2::copy_section

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling start sections and exports with adversarial names, drive `runtime/near-vm-runner/src/prepare/prepare_v2.rs::copy_section` to execute code outside the invoked method or before metering starts, breaking the invariant that no wasm executes before metering and entry validation, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/prepare_v2.rs` -> `copy_section`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: start sections and exports with adversarial names
- Exploit idea: execute code outside the invoked method or before metering starts
- Invariant to test: no wasm executes before metering and entry validation
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
