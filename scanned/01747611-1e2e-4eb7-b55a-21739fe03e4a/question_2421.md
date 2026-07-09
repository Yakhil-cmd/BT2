# Q2421: Omit context from rerandomization

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `verify` so `challenge-derived RNG` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlog.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `challenge-derived RNG` helper material.
- Invariant to test: Derived or rerandomized `challenge-derived RNG` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::verify` that feeds crafted `challenge-derived RNG` / `forked transcript` inputs, then assert whether downstream verification accepts an output that should have been rejected.
