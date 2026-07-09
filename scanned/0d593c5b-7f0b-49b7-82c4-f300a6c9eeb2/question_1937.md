# Q1937: Reorder rounds

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and reorder attacker-controlled `derived verifying key` messages so `keygen` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Deliver later-round `derived verifying key` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `derived verifying key` data must never satisfy earlier-round `private share` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `derived verifying key` / `private share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
