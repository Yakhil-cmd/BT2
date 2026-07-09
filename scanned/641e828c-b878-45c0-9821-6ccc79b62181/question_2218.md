# Q2218: Substitute app or public key

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `serialized scalar` for attacker-chosen `interpolation set` while keeping the rest of `values` valid enough that `batch_invert` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `serialized scalar` outputs must be bound to the exact `interpolation set` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `serialized scalar` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
