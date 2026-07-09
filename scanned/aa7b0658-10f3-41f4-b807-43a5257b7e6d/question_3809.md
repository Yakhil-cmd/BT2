# Q3809: Substitute app or public key

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `serialized scalar` for attacker-chosen `deserialize` while keeping the rest of `deserializer` valid enough that `deserialize` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::deserialize`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `deserializer`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `serialized scalar` outputs must be bound to the exact `deserialize` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::deserialize` that feeds crafted `serialized scalar` / `deserialize` inputs, then assert whether downstream verification accepts an output that should have been rejected.
