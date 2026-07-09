# Q2117: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `domain-separated hash` messages so `compute` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Deliver later-round `domain-separated hash` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `domain-separated hash` data must never satisfy earlier-round `polynomial commitment` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `domain-separated hash` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
