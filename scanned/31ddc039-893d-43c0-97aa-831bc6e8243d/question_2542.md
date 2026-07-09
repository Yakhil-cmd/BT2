# Q2542: Exploit non-canonical decoding

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use multiple encodings of `build` so `challenge_then_build_rng` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge_then_build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `challenge_label`
- Exploit idea: Pass non-canonical or edge-case encodings of `build` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `build` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge_then_build_rng` that feeds crafted `build` / `challenge-derived RNG` inputs, then assert whether downstream verification accepts an output that should have been rejected.
