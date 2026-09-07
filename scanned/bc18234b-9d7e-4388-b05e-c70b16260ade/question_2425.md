# Q2425: verifyKzgProof - accept an infinity proof via NodeJs [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyKzgProof via kzg.cxx (used by Lodestar)` with the G1 generator point, make c-kzg-4844 break the invariant that *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/node.js kzg.verifyKzgProof via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the proof and a y/z that makes the pairing trivially balance (the G1 generator point).
- Invariant to test: *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim (input: the G1 generator point).
