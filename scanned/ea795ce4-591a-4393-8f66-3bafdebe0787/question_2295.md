# Q2295: Substitute app or public key

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `hash output` for attacker-chosen `hash output` while keeping the rest of `identifiers`, `shares`, `point` valid enough that `eval_exponent_interpolation` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_exponent_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `hash output` outputs must be bound to the exact `hash output` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_exponent_interpolation` that feeds crafted `hash output` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
