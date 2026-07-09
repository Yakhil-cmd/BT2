# Q176: Alias two identities into one slot

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `participant`, `threshold`, `old_participants`, `session_id`, `protocol message timing` so `verify_proof_of_knowledge` treats two logical participants or sessions as the same `of` slot, overwrites state, and leads to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `threshold`, `old_participants`, `session_id`, `protocol message timing`
- Exploit idea: Create two attacker-controlled representations that collide onto one `of` slot inside maps or buffers.
- Invariant to test: No attacker-controlled alias may overwrite another participant's state slot or session slot.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `of` data into `verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
