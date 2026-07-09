# Q2412: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `challenge-derived RNG` variants into `verify` so different honest parties bind different views of `proof encoding` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlog.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Feed different `challenge-derived RNG` values to different honest parties and test whether `proof encoding` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `challenge-derived RNG` / `proof encoding` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::verify` that feeds crafted `challenge-derived RNG` / `proof encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
