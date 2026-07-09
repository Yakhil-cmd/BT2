# Q3978: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `set` variants into `set_non_identity_constant` so different honest parties bind different views of `constant` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Feed different `set` values to different honest parties and test whether `constant` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `set` / `constant` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `set` / `constant` inputs, then assert whether downstream verification accepts an output that should have been rejected.
