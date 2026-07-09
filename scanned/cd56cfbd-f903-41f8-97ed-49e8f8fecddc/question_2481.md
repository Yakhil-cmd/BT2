# Q2481: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `transcript`, `statement`, `proof` so each local sub-check inside `verify` accepts its own `statement encoding` fragment, but the combined global statement over `transcript state` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Make each local check over `statement encoding` pass independently, then verify whether the combined global statement over `transcript state` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `statement encoding` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::verify` that feeds crafted `statement encoding` / `transcript state` inputs, then assert whether downstream verification accepts an output that should have been rejected.
