# Q1181: verifyCellKzgProofBatch - weighted-proof coset power error via Nim [cell-index-63-last-data-column]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with cell_index 63 (last data column), make c-kzg-4844 break the invariant that each proof's weight == r^i * h_k^n for its true column so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: get_coset_shift_pow_for_cell)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: cell_index 63 (last data column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe get_coset_shift_pow_for_cell (cell_idx_rbl * FIELD_ELEMENTS_PER_CELL) for a wrong h_k^n weight (cell_index 63 (last data column)).
- Invariant to test: each proof's weight == r^i * h_k^n for its true column.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: each proof's weight == r^i * h_k^n for its true column (input: cell_index 63 (last data column)).
