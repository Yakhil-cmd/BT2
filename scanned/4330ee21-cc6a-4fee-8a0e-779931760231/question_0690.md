# Q690: Collide transcript domains

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `session_id`, `domain_separator`, `big_r`, `id`, `protocol message timing` so `challenge` reuses a transcript, hash, or domain-separation space for both `old participant set` and `received share`, enabling Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `session_id`, `domain_separator`, `big_r`, `id`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `old participant set` and `received share` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `old participant set` namespace from every `received share` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `challenge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
