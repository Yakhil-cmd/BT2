# Q3835: validation/instrument differential in prepare_v3::run

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling modules accepted by one preparation version and rejected by another, drive `runtime/near-vm-runner/src/prepare/prepare_v3.rs::run` to have two preparation paths disagree about the same module, breaking the invariant that all enabled preparation paths agree on module acceptance, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/prepare_v3.rs` -> `run`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: modules accepted by one preparation version and rejected by another
- Exploit idea: have two preparation paths disagree about the same module
- Invariant to test: all enabled preparation paths agree on module acceptance
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
