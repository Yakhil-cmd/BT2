# Q3506: signature-binding gap in verifier::verify_and_charge_tx_ephemeral

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling the fields hashed into the signed message versus the fields actually executed, drive `runtime/runtime/src/verifier.rs::verify_and_charge_tx_ephemeral` to execute a transaction whose executed content differs from the signed content, breaking the invariant that every executed field of a transaction is covered by the verified signature, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `verify_and_charge_tx_ephemeral`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: the fields hashed into the signed message versus the fields actually executed
- Exploit idea: execute a transaction whose executed content differs from the signed content
- Invariant to test: every executed field of a transaction is covered by the verified signature
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
