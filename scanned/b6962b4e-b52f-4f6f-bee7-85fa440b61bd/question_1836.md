# Q1836: Replay across signing requests

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and replay a valid `coordinator-selected signer set` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `coordinator-selected signer set` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
