# Q2053: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `Lagrange coefficient` variants into `check` so different honest parties bind different views of `serialized group element` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Feed different `Lagrange coefficient` values to different honest parties and test whether `serialized group element` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `Lagrange coefficient` / `serialized group element` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `Lagrange coefficient` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
