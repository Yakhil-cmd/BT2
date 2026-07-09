# Q2055: Alias two identities into one slot

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `val`, `r` so `check` treats two logical participants or sessions as the same `domain-separated hash` slot, overwrites state, and leads to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Create two attacker-controlled representations that collide onto one `domain-separated hash` slot inside maps or buffers.
- Invariant to test: No attacker-controlled alias may overwrite another participant's state slot or session slot.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `domain-separated hash` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
