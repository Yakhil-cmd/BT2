# Q3491: Replay across signing requests

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and replay a valid `private share` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `private share` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `private share` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
