# Q1989: Reorder rounds

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and reorder attacker-controlled `derived signing share` messages so `reshare` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Deliver later-round `derived signing share` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `derived signing share` data must never satisfy earlier-round `keygen output` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `derived signing share` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
