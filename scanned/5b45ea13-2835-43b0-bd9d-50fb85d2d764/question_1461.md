# Q1461: Leak sensitive state through output

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and choose `participants`, `sid`, `av_iv`, `bv_iv`, `protocol message timing` so repeated calls to `multiplication_many` expose share-dependent structure in `bit-matrix expansion` or `triple share` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/multiplication.rs::multiplication_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `sid`, `av_iv`, `bv_iv`, `protocol message timing`
- Exploit idea: Query `bit-matrix expansion` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `bit-matrix expansion` or `triple share`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `bit-matrix expansion` data into `multiplication_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
