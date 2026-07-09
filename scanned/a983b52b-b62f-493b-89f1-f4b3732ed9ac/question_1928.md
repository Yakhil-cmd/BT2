# Q1928: Collide transcript domains

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and choose `participants`, `threshold` so `keygen` reuses a transcript, hash, or domain-separation space for both `threshold` and `private share`, enabling Cryptographic flaws?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `threshold` and `private share` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `threshold` namespace from every `private share` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `threshold` / `private share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
