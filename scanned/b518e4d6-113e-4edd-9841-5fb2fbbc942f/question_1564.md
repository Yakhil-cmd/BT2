# Q1564: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` and send recipient-specific `rerandomized presignature` variants into `presign` so different honest parties bind different views of `presign` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Feed different `rerandomized presignature` values to different honest parties and test whether `presign` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `rerandomized presignature` / `presign` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `rerandomized presignature` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
