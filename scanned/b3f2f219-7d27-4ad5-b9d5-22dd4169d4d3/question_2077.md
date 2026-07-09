# Q2077: Validate same bytes under two meanings

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and submit the same raw `polynomial commitment` bytes under two semantic interpretations so `check` accepts both paths even though only one should be valid, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Submit identical raw bytes for `polynomial commitment` under two semantic interpretations and test whether both verification paths accept them.
- Invariant to test: The same `polynomial commitment` bytes must not validate under multiple semantic domains, roles, or curve/group interpretations.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `polynomial commitment` / `check` inputs, then assert whether downstream verification accepts an output that should have been rejected.
