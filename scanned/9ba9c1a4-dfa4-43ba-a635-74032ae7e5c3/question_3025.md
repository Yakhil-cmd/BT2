# Q3025: preparation cost blowup in prepare_v2::prepare_contract

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling wasm with pathological section, type and function-table shapes, drive `runtime/near-vm-runner/src/prepare/prepare_v2.rs::prepare_contract` to make preparation cost super-linear in the fee-charged code size, breaking the invariant that preparation work is linear in the charged code size, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/prepare_v2.rs` -> `prepare_contract`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: wasm with pathological section, type and function-table shapes
- Exploit idea: make preparation cost super-linear in the fee-charged code size
- Invariant to test: preparation work is linear in the charged code size
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
