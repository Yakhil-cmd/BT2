# Q2925: recoverCellsAndKzgProofs - vanishing polynomial correctness via NodeJs [cell-index-127-cells-per-ext-blob-1-last]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.recoverCellsAndKzgProofs via kzg.cxx (used by Lodestar)` with cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column), make c-kzg-4844 break the invariant that Z(x) roots == the missing columns' evaluation points, nothing more or less so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: recover_cells_and_kzg_proofs (helper: vanishing_polynomial_for_missing_cells)
- Entrypoint: bindings/node.js kzg.recoverCellsAndKzgProofs via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm vanishing_polynomial_for_missing_cells zeros exactly on the missing columns' cosets (cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column)).
- Invariant to test: Z(x) roots == the missing columns' evaluation points, nothing more or less.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: Z(x) roots == the missing columns' evaluation points, nothing more or less (input: cell_index 127 = CELLS_PER_EXT_BLOB-1 (last column)).
