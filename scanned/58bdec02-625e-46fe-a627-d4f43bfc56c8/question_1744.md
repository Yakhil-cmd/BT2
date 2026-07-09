# Q1744: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and send recipient-specific `participant identifier` variants into `presign` so different honest parties bind different views of `coordinator-selected signer set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Feed different `participant identifier` values to different honest parties and test whether `coordinator-selected signer set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `participant identifier` / `coordinator-selected signer set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
