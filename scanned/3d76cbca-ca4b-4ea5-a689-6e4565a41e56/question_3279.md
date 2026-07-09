# Q3279: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and reorder attacker-controlled `scalar wrapper` messages so `HID` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::HID`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `m`, `protocol message timing`
- Exploit idea: Deliver later-round `scalar wrapper` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `scalar wrapper` data must never satisfy earlier-round `big_c` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `scalar wrapper` data into `HID`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
