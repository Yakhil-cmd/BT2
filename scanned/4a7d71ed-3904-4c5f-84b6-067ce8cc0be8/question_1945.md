# Q1945: Replay across signing requests

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and replay a valid `participant set` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `participant set` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `participant set` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
