# Q2424: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `statement encoding` messages so `verify` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlog.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Deliver later-round `statement encoding` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `statement encoding` data must never satisfy earlier-round `statement encoding` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::verify` that feeds crafted `statement encoding` / `statement encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
