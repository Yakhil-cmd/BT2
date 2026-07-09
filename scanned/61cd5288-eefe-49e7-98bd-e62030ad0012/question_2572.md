# Q2572: Omit context from rerandomization

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `fork` so `proof encoding` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::fork`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `data`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `proof encoding` helper material.
- Invariant to test: Derived or rerandomized `proof encoding` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::fork` that feeds crafted `proof encoding` / `proof encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
