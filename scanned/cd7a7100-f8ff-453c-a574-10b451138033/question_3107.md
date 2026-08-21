# Q3107: feature flag divergence in logic::keccak512

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling code that only executes under a specific runtime feature set, drive `runtime/near-vm-runner/src/wasmtime_runner/logic.rs::keccak512` to have nodes with different feature resolution disagree, breaking the invariant that enabled features are a pure function of the protocol version, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/wasmtime_runner/logic.rs` -> `keccak512`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: code that only executes under a specific runtime feature set
- Exploit idea: have nodes with different feature resolution disagree
- Invariant to test: enabled features are a pure function of the protocol version
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
