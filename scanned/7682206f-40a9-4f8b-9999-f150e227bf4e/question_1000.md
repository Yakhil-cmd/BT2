# Q1000: Collide transcript domains

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `header`, `to`, `data`, `protocol message timing` so `send_private` reuses a transcript, hash, or domain-separation space for both `shared channel` and `private channel`, enabling Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::send_private`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `to`, `data`, `protocol message timing`
- Exploit idea: Reuse transcript labels or domain-separated hashes across `shared channel` and `private channel` contexts and look for acceptance.
- Invariant to test: Domain separation must isolate every `shared channel` namespace from every `private channel` namespace.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `shared channel` data into `send_private`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
