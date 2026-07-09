# Q2889: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and send recipient-specific `bit-matrix expansion` variants into `expand_transpose` so different honest parties bind different views of `alpha share` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::expand_transpose`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `sid`, `rows`, `protocol message timing`
- Exploit idea: Feed different `bit-matrix expansion` values to different honest parties and test whether `alpha share` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `bit-matrix expansion` / `alpha share` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `bit-matrix expansion` data into `expand_transpose`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
