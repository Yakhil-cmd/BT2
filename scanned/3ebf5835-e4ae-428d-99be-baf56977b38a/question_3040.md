# Q3040: import table abuse in prepare_v3::transform_import_section

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling imports naming nonexistent or duplicated host functions, drive `runtime/near-vm-runner/src/prepare/prepare_v3.rs::transform_import_section` to bind an import to a host function the protocol does not export, breaking the invariant that only the protocol's exported host functions can be imported, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/prepare_v3.rs` -> `transform_import_section`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: imports naming nonexistent or duplicated host functions
- Exploit idea: bind an import to a host function the protocol does not export
- Invariant to test: only the protocol's exported host functions can be imported
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
