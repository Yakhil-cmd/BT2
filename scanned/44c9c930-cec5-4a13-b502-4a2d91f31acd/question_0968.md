# Q968: Replay across signing requests

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a valid `send` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/protocol/internal.rs::send_many`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `data`, `protocol message timing`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `send` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `send` data into `send_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
