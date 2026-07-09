# Q2462: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `verify` variants into `verify` so different honest parties bind different views of `challenge-derived RNG` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Feed different `verify` values to different honest parties and test whether `challenge-derived RNG` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `verify` / `challenge-derived RNG` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::verify` that feeds crafted `verify` / `challenge-derived RNG` inputs, then assert whether downstream verification accepts an output that should have been rejected.
