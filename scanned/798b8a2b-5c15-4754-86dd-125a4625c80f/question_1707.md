# Q1707: Replay across signing requests

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` and replay a valid `key package` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `key package` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
