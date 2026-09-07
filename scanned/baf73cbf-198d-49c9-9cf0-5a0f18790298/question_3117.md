# Q3117: blobToKzgCommitment - commitment from a non-canonical blob element via Nim [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.blobToKzgCommitment (used by Nimbus)` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that every field element committed == the canonical decode of the blob bytes, or the call returns C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: blob_to_kzg_commitment (helper: blob_to_polynomial)
- Entrypoint: bindings/nim kzg.blobToKzgCommitment (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: put a non-canonical 32-byte field element in the blob and check blob_to_polynomial/bytes_to_bls_field rejects it before poly_to_kzg_commitment runs (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: every field element committed == the canonical decode of the blob bytes, or the call returns C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: every field element committed == the canonical decode of the blob bytes, or the call returns C_KZG_BADARGS (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
