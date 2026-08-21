# Q3018: preparation cost blowup in instrument_v3::transform_name_section

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling wasm with pathological section, type and function-table shapes, drive `runtime/near-vm-runner/src/prepare/instrument_v3.rs::transform_name_section` to make preparation cost super-linear in the fee-charged code size, breaking the invariant that preparation work is linear in the charged code size, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/instrument_v3.rs` -> `transform_name_section`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: wasm with pathological section, type and function-table shapes
- Exploit idea: make preparation cost super-linear in the fee-charged code size
- Invariant to test: preparation work is linear in the charged code size
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
