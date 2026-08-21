# Q2321: deploy cost undercharge in contract::record_deploy

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling code size and compile complexity at the configured limits, drive `core/store/src/contract.rs::record_deploy` to pay a deploy fee far below the compilation work the network performs, breaking the invariant that deployment fees cover the worst-case preparation and compilation cost, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/store/src/contract.rs` -> `record_deploy`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: code size and compile complexity at the configured limits
- Exploit idea: pay a deploy fee far below the compilation work the network performs
- Invariant to test: deployment fees cover the worst-case preparation and compilation cost
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
