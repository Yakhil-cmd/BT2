# Q2234: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `serialized scalar` variants into `commit_polynomial` so different honest parties bind different views of `hash output` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::commit_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `polynomial commitment`, `Lagrange coefficient`
- Exploit idea: Feed different `serialized scalar` values to different honest parties and test whether `hash output` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `serialized scalar` / `hash output` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::commit_polynomial` that feeds crafted `serialized scalar` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
