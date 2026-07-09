# Q292: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and swap `Beaver triple` for attacker-chosen `big_r` while keeping the rest of `participants`, `threshold`, `protocol message timing` valid enough that `do_generation` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::do_generation`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `Beaver triple` outputs must be bound to the exact `big_r` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `Beaver triple` data into `do_generation`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
