# Q3330: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and reorder attacker-controlled `curve` messages so `hash_to_curve` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::hash_to_curve`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Deliver later-round `curve` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `curve` data must never satisfy earlier-round `curve` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `curve` data into `hash_to_curve`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
