# Q273: code cache poisoning in global_contract::try_from

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling redeploy timing versus compiled-code cache keys, drive `core/primitives-core/src/global_contract.rs::try_from` to serve a cached compilation that does not correspond to the current code, breaking the invariant that the compilation cache is keyed so that entry and code correspond exactly, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives-core/src/global_contract.rs` -> `try_from`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: redeploy timing versus compiled-code cache keys
- Exploit idea: serve a cached compilation that does not correspond to the current code
- Invariant to test: the compilation cache is keyed so that entry and code correspond exactly
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
