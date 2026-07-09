# Q76: Exploit non-canonical decoding

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and use multiple encodings of `old participant set` so `do_keygen` deserializes semantically distinct attacker inputs into the same accepted value, enabling Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_keygen`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Pass non-canonical or edge-case encodings of `old participant set` and compare accepted decoded values across implementations.
- Invariant to test: Deserialization of `old participant set` must be canonical and reject malformed or ambiguous encodings.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `do_keygen`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
