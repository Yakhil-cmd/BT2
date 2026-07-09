# Q2502: Abuse normalization ambiguity

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `seed` so `build_rng` normalizes two semantically different `build` states into one accepted output, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Construct inputs that normalize to the same accepted form while representing different semantic signer or key states.
- Invariant to test: Normalization must not collapse two distinct `build` states into one accepted result.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `build` / `generator binding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
