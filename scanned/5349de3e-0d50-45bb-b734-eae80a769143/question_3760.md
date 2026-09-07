# Q3760: computeBlobKzgProof - non-canonical commitment argument via Nim [a-compressed-point-with-the-sign-y-bit-f]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.computeBlobKzgProof (used by Nimbus)` with a compressed point with the sign/y-bit flipped, make c-kzg-4844 break the invariant that the commitment used == the canonical validated point, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_blob_kzg_proof (helper: bytes_to_kzg_commitment)
- Entrypoint: bindings/nim kzg.computeBlobKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a compressed point with the sign/y-bit flipped. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a non-canonical/inf commitment and confirm bytes_to_kzg_commitment gates it before compute_challenge (a compressed point with the sign/y-bit flipped).
- Invariant to test: the commitment used == the canonical validated point, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: the commitment used == the canonical validated point, else C_KZG_BADARGS (input: a compressed point with the sign/y-bit flipped).
