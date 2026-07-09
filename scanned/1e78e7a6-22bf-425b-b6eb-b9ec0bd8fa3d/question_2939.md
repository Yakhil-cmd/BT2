# Q2939: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and send recipient-specific `alpha share` variants into `from_rows` so different honest parties bind different views of `OT transcript` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::from_rows`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `rows`, `protocol message timing`
- Exploit idea: Feed different `alpha share` values to different honest parties and test whether `OT transcript` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `alpha share` / `OT transcript` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `alpha share` data into `from_rows`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
