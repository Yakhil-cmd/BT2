# Q531: Replay across signing requests

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and replay a valid `nonce commitment` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/frost/mod.rs::do_presign`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `signing_share`, `protocol message timing`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `nonce commitment` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
