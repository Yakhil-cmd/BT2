# Q2497: verifyKzgProof - verify agrees with compute via Nim [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyKzgProof (used by Nimbus)` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that verify_kzg_proof(compute_kzg_proof(blob,z)) == true for every blob and z so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/nim kzg.verifyKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm verify_kzg_proof accepts exactly the (proof,y) that compute_kzg_proof produced for the same z (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: verify_kzg_proof(compute_kzg_proof(blob,z)) == true for every blob and z.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: verify_kzg_proof(compute_kzg_proof(blob,z)) == true for every blob and z (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
