# Q3825: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `at` variants into `eval_at_participant` so different honest parties bind different views of `eval` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_participant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participant`
- Exploit idea: Feed different `at` values to different honest parties and test whether `eval` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `at` / `eval` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_participant` that feeds crafted `at` / `eval` inputs, then assert whether downstream verification accepts an output that should have been rejected.
