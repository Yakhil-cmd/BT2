# Q2408: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `transcript`, `statement`, `witness`, `nonce` so each local sub-check inside `prove_with_nonce` accepts its own `prove` fragment, but the combined global statement over `challenge` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/dlog.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `nonce`
- Exploit idea: Make each local check over `prove` pass independently, then verify whether the combined global statement over `challenge` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `prove` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::prove_with_nonce` that feeds crafted `prove` / `challenge` inputs, then assert whether downstream verification accepts an output that should have been rejected.
