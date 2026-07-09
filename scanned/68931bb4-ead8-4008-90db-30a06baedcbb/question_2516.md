# Q2516: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `forked transcript` so `challenge` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `dest`
- Exploit idea: Pass non-canonical or edge-case encodings of `forked transcript` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `forked transcript` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge` that feeds crafted `forked transcript` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
