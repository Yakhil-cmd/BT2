# Q1963: Reorder rounds

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and reorder attacker-controlled `refresh` messages so `refresh` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Deliver later-round `refresh` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `refresh` data must never satisfy earlier-round `refresh` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `refresh` / `refresh` inputs, then assert whether downstream verification accepts an output that should have been rejected.
