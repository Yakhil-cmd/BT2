# Q5659: verifyKzgProof - non-canonical z accepted via Nim [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyKzgProof (used by Nimbus)` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/nim kzg.verifyKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply a z above the modulus and confirm bytes_to_bls_field rejects before pairing (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false (input: 2^256 - r (wraps to a small residue if reduced without the check)).
