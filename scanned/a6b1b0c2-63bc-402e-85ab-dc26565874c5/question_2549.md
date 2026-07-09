# Q2549: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `witness` messages so `challenge_then_build_rng` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge_then_build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `challenge_label`
- Exploit idea: Deliver later-round `witness` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `witness` data must never satisfy earlier-round `witness` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge_then_build_rng` that feeds crafted `witness` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
