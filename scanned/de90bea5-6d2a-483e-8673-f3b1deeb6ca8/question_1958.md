# Q1958: key recovery misuse in signature::key_type

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling recovery ids and malformed public key encodings, drive `core/crypto/src/signature.rs::key_type` to recover a public key that authorises an account the attacker does not own, breaking the invariant that key recovery never yields a key that was not used to sign, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/crypto/src/signature.rs` -> `key_type`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: recovery ids and malformed public key encodings
- Exploit idea: recover a public key that authorises an account the attacker does not own
- Invariant to test: key recovery never yields a key that was not used to sign
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
