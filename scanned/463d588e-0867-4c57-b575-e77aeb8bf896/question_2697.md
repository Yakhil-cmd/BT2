# Q2697: verifyCellKzgProofBatch - duplicate (commitment,cell_index) accepted via Nim [cell-index-127-cells-per-ext-blob-1-last]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column), make c-kzg-4844 break the invariant that *ok true iff every supplied cell lies on its commitment's polynomial; duplicate columns cannot average into acceptance so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: compute_commitment_to_aggregated_interpolation_poly)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: submit the same column index twice for one commitment with two different cells so their r-weighted sum interpolates while neither cell is valid (cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column)).
- Invariant to test: *ok true iff every supplied cell lies on its commitment's polynomial; duplicate columns cannot average into acceptance.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: *ok true iff every supplied cell lies on its commitment's polynomial; duplicate columns cannot average into acceptance (input: cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column)).
