# Q3990: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `hash output` messages so `set_non_identity_constant` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Deliver later-round `hash output` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `hash output` data must never satisfy earlier-round `Lagrange coefficient` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `hash output` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
