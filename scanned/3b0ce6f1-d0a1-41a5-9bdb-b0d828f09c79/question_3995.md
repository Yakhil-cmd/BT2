# Q3995: Abuse normalization ambiguity

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `v` so `set_non_identity_constant` normalizes two semantically different `serialized scalar` states into one accepted output, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Construct inputs that normalize to the same accepted form while representing different semantic signer or key states.
- Invariant to test: Normalization must not collapse two distinct `serialized scalar` states into one accepted result.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `serialized scalar` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
