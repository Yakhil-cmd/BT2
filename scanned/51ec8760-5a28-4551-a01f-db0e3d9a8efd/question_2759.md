# Q2759: cache poisoning across versions in cache::without_item_cap

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling redeploys spanning a VM or parameter version change, drive `runtime/near-vm-runner/src/cache.rs::without_item_cap` to reuse an artifact compiled under different parameters, breaking the invariant that cache entries are invalidated whenever compilation inputs change, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/cache.rs` -> `without_item_cap`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: redeploys spanning a VM or parameter version change
- Exploit idea: reuse an artifact compiled under different parameters
- Invariant to test: cache entries are invalidated whenever compilation inputs change
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
