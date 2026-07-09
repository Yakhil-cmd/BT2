# Q1980: Collide transcript domains

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and choose `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so `reshare` reuses a transcript, hash, or domain-separation space for both `derived signing share` and `threshold`, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `derived signing share` and `threshold` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `derived signing share` namespace from every `threshold` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `derived signing share` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
