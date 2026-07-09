# Q2404: Reuse helper output under new signer set

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and carry a previously valid `transcript state` helper output into a different participant set or threshold context where `prove_with_nonce` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlog.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `nonce`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `transcript state` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::prove_with_nonce` that feeds crafted `transcript state` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
