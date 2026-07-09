# Q2459: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `transcript`, `statement`, `witness`, `k` so each local sub-check inside `prove_with_nonce` accepts its own `challenge-derived RNG` fragment, but the combined global statement over `prove` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `k`
- Exploit idea: Make each local check over `challenge-derived RNG` pass independently, then verify whether the combined global statement over `prove` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `challenge-derived RNG` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::prove_with_nonce` that feeds crafted `challenge-derived RNG` / `prove` inputs, then assert whether downstream verification accepts an output that should have been rejected.
