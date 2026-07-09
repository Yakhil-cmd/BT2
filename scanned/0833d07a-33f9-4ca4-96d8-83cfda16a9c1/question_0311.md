# Q311: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and send recipient-specific `beta share` variants into `do_generation_many` so different honest parties bind different views of `bit-matrix expansion` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::do_generation_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Feed different `beta share` values to different honest parties and test whether `bit-matrix expansion` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `beta share` / `bit-matrix expansion` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `beta share` data into `do_generation_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
