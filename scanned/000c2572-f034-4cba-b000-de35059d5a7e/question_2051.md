# Q2051: contract-code size limit in code::take_code

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling wasm exactly at and just past `max_contract_size`, drive `core/primitives-core/src/code.rs::take_code` to store code larger than the protocol limit permits, breaking the invariant that stored contract code never exceeds the configured maximum size, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/primitives-core/src/code.rs` -> `take_code`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: wasm exactly at and just past `max_contract_size`
- Exploit idea: store code larger than the protocol limit permits
- Invariant to test: stored contract code never exceeds the configured maximum size
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
