# Q1161: verifyCellKzgProofBatch - non-canonical cell field element via Nim [r-1-smallest-non-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with r+1 (smallest non-canonical scalar), make c-kzg-4844 break the invariant that the field element aggregated == canonical decode of the cell bytes, else BADARGS before *ok can be true so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: compute_commitment_to_aggregated_interpolation_poly)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: r+1 (smallest non-canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: put a non-canonical element in a cell; note the challenge hashes raw bytes before bytes_to_bls_field validates them (r+1 (smallest non-canonical scalar)).
- Invariant to test: the field element aggregated == canonical decode of the cell bytes, else BADARGS before *ok can be true.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: the field element aggregated == canonical decode of the cell bytes, else BADARGS before *ok can be true (input: r+1 (smallest non-canonical scalar)).
