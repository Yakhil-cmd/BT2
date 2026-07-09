# Q362: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and send recipient-specific `max_malicious bound` variants into `do_sign_coordinator` so different honest parties bind different views of `rerandomized presignature` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Feed different `max_malicious bound` values to different honest parties and test whether `rerandomized presignature` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `max_malicious bound` / `rerandomized presignature` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `max_malicious bound` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
