# Q2512: Swap participant ordering

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with crafted `label`, `dest` and exploit `challenge` so participant ordering or identifier mapping for `statement encoding` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `dest`
- Exploit idea: Reorder or relabel participant-specific `statement encoding` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge` that feeds crafted `statement encoding` / `forked transcript` inputs, then assert whether downstream verification accepts an output that should have been rejected.
