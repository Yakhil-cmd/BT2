# Q2129: Validate same bytes under two meanings

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and submit the same raw `interpolation set` bytes under two semantic interpretations so `compute` accepts both paths even though only one should be valid, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Submit identical raw bytes for `interpolation set` under two semantic interpretations and test whether both verification paths accept them.
- Invariant to test: The same `interpolation set` bytes must not validate under multiple semantic domains, roles, or curve/group interpretations.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `interpolation set` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
