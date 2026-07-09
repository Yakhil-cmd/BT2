# Q100: Collide transcript domains

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing` so `do_keyshare` reuses a transcript, hash, or domain-separation space for both `old participant set` and `domain_separator`, enabling Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_keyshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `old participant set` and `domain_separator` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `old participant set` namespace from every `domain_separator` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `do_keyshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
