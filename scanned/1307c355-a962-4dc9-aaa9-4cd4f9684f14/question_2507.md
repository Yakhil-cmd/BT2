# Q2507: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `seed` so each local sub-check inside `build_rng` accepts its own `rng` fragment, but the combined global statement over `rng` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Make each local check over `rng` pass independently, then verify whether the combined global statement over `rng` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `rng` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `rng` / `rng` inputs, then assert whether downstream verification accepts an output that should have been rejected.
