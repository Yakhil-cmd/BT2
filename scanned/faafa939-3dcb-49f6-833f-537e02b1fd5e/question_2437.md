# Q2437: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `witness` variants into `prove_with_nonce` so different honest parties bind different views of `proof encoding` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `k`
- Exploit idea: Feed different `witness` values to different honest parties and test whether `proof encoding` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `witness` / `proof encoding` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::prove_with_nonce` that feeds crafted `witness` / `proof encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
