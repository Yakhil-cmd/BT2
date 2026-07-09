# Q3962: Substitute app or public key

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `interpolation set` for attacker-chosen `interpolation set` while keeping the rest of `secret`, `degree` valid enough that `generate_polynomial` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::generate_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `secret`, `degree`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `interpolation set` outputs must be bound to the exact `interpolation set` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::generate_polynomial` that feeds crafted `interpolation set` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
