# Q741: Collide transcript domains

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `commitments`, `protocol message timing` so `public_key_from_commitments` reuses a transcript, hash, or domain-separation space for both `new participant set` and `received share`, enabling Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `new participant set` and `received share` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `new participant set` namespace from every `received share` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
