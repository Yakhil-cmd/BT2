# Q2427: verifyKzgProof - accept an infinity proof via Nim [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyKzgProof (used by Nimbus)` with the G1 generator point, make c-kzg-4844 break the invariant that *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/nim kzg.verifyKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the proof and a y/z that makes the pairing trivially balance (the G1 generator point).
- Invariant to test: *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim (input: the G1 generator point).
