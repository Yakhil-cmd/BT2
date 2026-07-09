# Q2105: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `polynomial` variants into `compute` so different honest parties bind different views of `interpolation set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Feed different `polynomial` values to different honest parties and test whether `interpolation set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `polynomial` / `interpolation set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `polynomial` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
