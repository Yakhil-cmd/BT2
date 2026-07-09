# Q2487: Alias two identities into one slot

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `seed` so `build_rng` treats two logical participants or sessions as the same `statement encoding` slot, overwrites state, and leads to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Create two attacker-controlled representations that collide onto one `statement encoding` slot inside maps or buffers.
- Invariant to test: No attacker-controlled alias may overwrite another participant's state slot or session slot.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `statement encoding` / `statement encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
