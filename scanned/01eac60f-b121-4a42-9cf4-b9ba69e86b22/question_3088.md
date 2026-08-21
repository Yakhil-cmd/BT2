# Q3088: compilation resource blowup in logic::finite_wasm_stack

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling wasm that maximises compile time and memory per byte, drive `runtime/near-vm-runner/src/wasmtime_runner/logic.rs::finite_wasm_stack` to exhaust validator CPU or memory during compilation for a small fee, breaking the invariant that compilation cost is bounded by the deploy fee, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/wasmtime_runner/logic.rs` -> `finite_wasm_stack`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: wasm that maximises compile time and memory per byte
- Exploit idea: exhaust validator CPU or memory during compilation for a small fee
- Invariant to test: compilation cost is bounded by the deploy fee
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
