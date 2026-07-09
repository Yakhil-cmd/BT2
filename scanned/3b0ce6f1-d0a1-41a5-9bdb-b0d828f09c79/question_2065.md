# Q2065: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `serialized scalar` messages so `check` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Deliver later-round `serialized scalar` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `serialized scalar` data must never satisfy earlier-round `serialized scalar` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `serialized scalar` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
