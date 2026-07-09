# Q1764: Alias two identities into one slot

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and craft `participants`, `args`, `protocol message timing` so `presign` treats two logical participants or sessions as the same `presign` slot, overwrites state, and leads to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Create two attacker-controlled representations that collide onto one `presign` slot inside maps or buffers.
- Invariant to test: No attacker-controlled alias may overwrite another participant's state slot or session slot.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
