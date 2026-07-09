# Q2373: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `hash output` messages so `verify` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Deliver later-round `hash output` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `hash output` data must never satisfy earlier-round `verify` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `hash output` / `verify` inputs, then assert whether downstream verification accepts an output that should have been rejected.
