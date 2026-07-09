# Q3364: Replay across signing requests

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and replay a valid `app_pk` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::hash_to_scalar`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `domain`, `msg`, `protocol message timing`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `app_pk` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_pk` data into `hash_to_scalar`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
