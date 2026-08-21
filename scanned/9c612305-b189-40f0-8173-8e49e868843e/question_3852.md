# Q3852: signer-account mismatch in access_keys::access_key_storage_usage

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling `signer_id` and the public key used to sign, drive `runtime/runtime/src/access_keys.rs::access_key_storage_usage` to authorise an action with a key that belongs to a different account, breaking the invariant that the signing key must be an access key of the named signer account, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/access_keys.rs` -> `access_key_storage_usage`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: `signer_id` and the public key used to sign
- Exploit idea: authorise an action with a key that belongs to a different account
- Invariant to test: the signing key must be an access key of the named signer account
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
