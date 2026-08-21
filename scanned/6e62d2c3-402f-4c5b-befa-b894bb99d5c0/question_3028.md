# Q3028: memory limit bypass in prepare_v2::size_of_value

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling initial and maximum memory declarations at the limit boundaries, drive `runtime/near-vm-runner/src/prepare/prepare_v2.rs::size_of_value` to grow guest memory past the configured maximum, breaking the invariant that guest memory never exceeds the configured maximum pages, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/prepare_v2.rs` -> `size_of_value`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: initial and maximum memory declarations at the limit boundaries
- Exploit idea: grow guest memory past the configured maximum
- Invariant to test: guest memory never exceeds the configured maximum pages
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
