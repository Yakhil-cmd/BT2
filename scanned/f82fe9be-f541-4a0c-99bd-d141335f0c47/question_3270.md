# Q3270: verifyKzgProof - z at the modulus boundary via Nim [a-value-in-r-2-256-that-blst-scalar-fr-c]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyKzgProof (used by Nimbus)` with a value in [r, 2^256) that blst_scalar_fr_check must reject, make c-kzg-4844 break the invariant that z accepted iff canonical; verdict matches the reference at the boundary so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/nim kzg.verifyKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a value in [r, 2^256) that blst_scalar_fr_check must reject. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe z exactly at r and r-1 for a canonical-check off-by-one (a value in [r, 2^256) that blst_scalar_fr_check must reject).
- Invariant to test: z accepted iff canonical; verdict matches the reference at the boundary.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: z accepted iff canonical; verdict matches the reference at the boundary (input: a value in [r, 2^256) that blst_scalar_fr_check must reject).
