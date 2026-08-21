# Q3837: feature gate bypass in prepare_v3::size_of_value

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling wasm using proposals that are meant to be disabled, drive `runtime/near-vm-runner/src/prepare/prepare_v3.rs::size_of_value` to execute a wasm feature the protocol does not permit, breaking the invariant that only the explicitly enabled wasm features can be instantiated, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/prepare_v3.rs` -> `size_of_value`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: wasm using proposals that are meant to be disabled
- Exploit idea: execute a wasm feature the protocol does not permit
- Invariant to test: only the explicitly enabled wasm features can be instantiated
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
