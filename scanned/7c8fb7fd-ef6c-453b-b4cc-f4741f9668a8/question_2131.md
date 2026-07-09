# Q2131: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `interpolation set` variants into `domain_separate_hash` so different honest parties bind different views of `domain-separated hash` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/hash.rs::domain_separate_hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain_separator`, `data`
- Exploit idea: Feed different `interpolation set` values to different honest parties and test whether `domain-separated hash` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `interpolation set` / `domain-separated hash` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::hash::domain_separate_hash` that feeds crafted `interpolation set` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
