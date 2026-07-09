# Q2505: Replay across signing requests

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a valid `challenge-derived RNG` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `challenge-derived RNG` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `challenge-derived RNG` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
