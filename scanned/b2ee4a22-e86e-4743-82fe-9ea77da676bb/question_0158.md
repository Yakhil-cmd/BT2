# Q158: verifyBlobKzgProof - non-canonical blob element in verify via Nim [the-value-equal-to-the-bls-modulus-r-0x7]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProof (used by Nimbus)` with the value equal to the BLS modulus r (0x7300, make c-kzg-4844 break the invariant that each blob element == canonical decode, else BADARGS and *ok stays false so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: blob_to_polynomial)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: put a non-canonical element in the blob and confirm blob_to_polynomial rejects before pairing (the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
- Invariant to test: each blob element == canonical decode, else BADARGS and *ok stays false.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: each blob element == canonical decode, else BADARGS and *ok stays false (input: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
