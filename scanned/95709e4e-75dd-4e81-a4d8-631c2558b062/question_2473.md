# Q2473: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `challenge-derived RNG` messages so `verify` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Deliver later-round `challenge-derived RNG` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `challenge-derived RNG` data must never satisfy earlier-round `witness` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::verify` that feeds crafted `challenge-derived RNG` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
