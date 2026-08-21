# Q3807: nondeterministic float in instrument_v3::checked_add_i64

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling float operations, NaN payloads and conversions, drive `runtime/near-vm-runner/src/prepare/instrument_v3.rs::checked_add_i64` to produce results that can differ between hosts or VM versions, breaking the invariant that wasm execution is bit-for-bit deterministic across nodes, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/instrument_v3.rs` -> `checked_add_i64`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: float operations, NaN payloads and conversions
- Exploit idea: produce results that can differ between hosts or VM versions
- Invariant to test: wasm execution is bit-for-bit deterministic across nodes
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
