# Q1392: trap classification drift in logic::gas_seen_from_wasm

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling wasm that traps in each distinct trap class, drive `runtime/near-vm-runner/src/wasmtime_runner/logic.rs::gas_seen_from_wasm` to have the same trap map to different outcomes on different nodes, breaking the invariant that every trap maps deterministically to one protocol-level error, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/wasmtime_runner/logic.rs` -> `gas_seen_from_wasm`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: wasm that traps in each distinct trap class
- Exploit idea: have the same trap map to different outcomes on different nodes
- Invariant to test: every trap maps deterministically to one protocol-level error
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
