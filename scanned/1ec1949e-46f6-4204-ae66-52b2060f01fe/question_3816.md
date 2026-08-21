# Q3816: panic in preparation in instrument_v3::transform_name_section

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling truncated, malformed and adversarially nested wasm sections, drive `runtime/near-vm-runner/src/prepare/instrument_v3.rs::transform_name_section` to panic or abort inside preparation instead of returning an error, breaking the invariant that malformed wasm always yields a typed preparation error, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/instrument_v3.rs` -> `transform_name_section`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: truncated, malformed and adversarially nested wasm sections
- Exploit idea: panic or abort inside preparation instead of returning an error
- Invariant to test: malformed wasm always yields a typed preparation error
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
