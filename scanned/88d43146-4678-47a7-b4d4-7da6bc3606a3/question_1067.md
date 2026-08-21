# Q1067: signature malleability in alt_bn128::encode_g1

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling alternative encodings of one signature over the same message, drive `runtime/near-vm-runner/src/logic/alt_bn128.rs::encode_g1` to get two distinct transactions accepted for one signed intent, breaking the invariant that a signed message admits exactly one accepted signature encoding, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/near-vm-runner/src/logic/alt_bn128.rs` -> `encode_g1`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: alternative encodings of one signature over the same message
- Exploit idea: get two distinct transactions accepted for one signed intent
- Invariant to test: a signed message admits exactly one accepted signature encoding
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
