# Q3734: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and swap `sigma share` for attacker-chosen `height` while keeping the rest of `triple share`, `Beaver triple`, `protocol message timing` valid enough that `height` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/bits.rs::height`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `triple share`, `Beaver triple`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `sigma share` outputs must be bound to the exact `height` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `height`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
