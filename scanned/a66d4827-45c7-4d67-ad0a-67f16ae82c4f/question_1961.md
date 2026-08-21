# Q1961: signature malleability in signature::ml_dsa_65_secret_from_seed

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling alternative encodings of one signature over the same message, drive `core/crypto/src/signature.rs::ml_dsa_65_secret_from_seed` to get two distinct transactions accepted for one signed intent, breaking the invariant that a signed message admits exactly one accepted signature encoding, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/crypto/src/signature.rs` -> `ml_dsa_65_secret_from_seed`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: alternative encodings of one signature over the same message
- Exploit idea: get two distinct transactions accepted for one signed intent
- Invariant to test: a signed message admits exactly one accepted signature encoding
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
