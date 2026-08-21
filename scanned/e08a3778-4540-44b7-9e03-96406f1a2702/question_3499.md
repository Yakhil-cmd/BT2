# Q3499: add-key privilege escalation in verifier::set_tx_state_changes

## Question
Can an unprivileged attacker who submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account, controlling an `AddKey` action creating a key with wider permissions than the signing key, drive `runtime/runtime/src/verifier.rs::set_tx_state_changes` to use a restricted key to mint a full-access key, breaking the invariant that a restricted key can never create a key with broader permissions than itself, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `set_tx_state_changes`
- Entrypoint: unprivileged attacker submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account
- Attacker controls: an `AddKey` action creating a key with wider permissions than the signing key
- Exploit idea: use a restricted key to mint a full-access key
- Invariant to test: a restricted key can never create a key with broader permissions than itself
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
