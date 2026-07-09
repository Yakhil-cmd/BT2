# Q2575: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `challenge-derived RNG` messages so `fork` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::fork`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `data`
- Exploit idea: Deliver later-round `challenge-derived RNG` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `challenge-derived RNG` data must never satisfy earlier-round `proof encoding` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::fork` that feeds crafted `challenge-derived RNG` / `proof encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
