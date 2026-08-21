# Q1322: panic in preparation in prepare_v2::prepare_contract

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling truncated, malformed and adversarially nested wasm sections, drive `runtime/near-vm-runner/src/prepare/prepare_v2.rs::prepare_contract` to panic or abort inside preparation instead of returning an error, breaking the invariant that malformed wasm always yields a typed preparation error, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/prepare_v2.rs` -> `prepare_contract`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: truncated, malformed and adversarially nested wasm sections
- Exploit idea: panic or abort inside preparation instead of returning an error
- Invariant to test: malformed wasm always yields a typed preparation error
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
