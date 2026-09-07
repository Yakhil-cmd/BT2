# Q4113: verifyBlobKzgProof - infinity commitment for a blob via Nim [an-all-zero-48-byte-string-with-every-fl]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProof (used by Nimbus)` with an all-zero 48-byte string with every flag clear, make c-kzg-4844 break the invariant that *ok true iff the infinity commitment truly commits to the blob polynomial so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: an all-zero 48-byte string with every flag clear. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment for a chosen blob and see whether the derived (challenge,y) still verifies (an all-zero 48-byte string with every flag clear).
- Invariant to test: *ok true iff the infinity commitment truly commits to the blob polynomial.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: *ok true iff the infinity commitment truly commits to the blob polynomial (input: an all-zero 48-byte string with every flag clear).
