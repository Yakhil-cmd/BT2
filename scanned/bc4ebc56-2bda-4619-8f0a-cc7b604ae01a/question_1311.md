# Q1311: import table abuse in instrument_v3::maybe_add_imports

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling imports naming nonexistent or duplicated host functions, drive `runtime/near-vm-runner/src/prepare/instrument_v3.rs::maybe_add_imports` to bind an import to a host function the protocol does not export, breaking the invariant that only the protocol's exported host functions can be imported, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/near-vm-runner/src/prepare/instrument_v3.rs` -> `maybe_add_imports`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: imports naming nonexistent or duplicated host functions
- Exploit idea: bind an import to a host function the protocol does not export
- Invariant to test: only the protocol's exported host functions can be imported
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
