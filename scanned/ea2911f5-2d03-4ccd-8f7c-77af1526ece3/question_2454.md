# Q2454: Abuse normalization ambiguity

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `transcript`, `statement`, `witness`, `k` so `prove_with_nonce` normalizes two semantically different `witness` states into one accepted output, enabling Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `k`
- Exploit idea: Construct inputs that normalize to the same accepted form while representing different semantic signer or key states.
- Invariant to test: Normalization must not collapse two distinct `witness` states into one accepted result.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::prove_with_nonce` that feeds crafted `witness` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
