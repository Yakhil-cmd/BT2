# Q2345: Substitute app or public key

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `polynomial commitment` for attacker-chosen `polynomial` while keeping the rest of `hash output`, `domain-separated hash` valid enough that `derive_randomness` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::derive_randomness`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `hash output`, `domain-separated hash`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `polynomial commitment` outputs must be bound to the exact `polynomial` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::derive_randomness` that feeds crafted `polynomial commitment` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
