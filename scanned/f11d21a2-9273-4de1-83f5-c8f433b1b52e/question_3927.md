# Q3927: Swap participant ordering

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with crafted `Lagrange coefficient`, `hash output` and exploit `extend_with_zero` so participant ordering or identifier mapping for `Lagrange coefficient` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `Lagrange coefficient`, `hash output`
- Exploit idea: Reorder or relabel participant-specific `Lagrange coefficient` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_zero` that feeds crafted `Lagrange coefficient` / `extend` inputs, then assert whether downstream verification accepts an output that should have been rejected.
