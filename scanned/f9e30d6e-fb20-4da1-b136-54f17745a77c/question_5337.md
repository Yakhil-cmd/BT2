# Q5337: recoverCellsAndKzgProofs - vanishing polynomial correctness via Zig [cell-index-128-cells-per-ext-blob-one-pa]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.recoverCellsAndKzgProofs via root.zig` with cell_index 128 = CELLS_PER_EXT_BLOB (one past the end), make c-kzg-4844 break the invariant that Z(x) roots == the missing columns' evaluation points, nothing more or less so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: recover_cells_and_kzg_proofs (helper: vanishing_polynomial_for_missing_cells)
- Entrypoint: bindings/zig Settings.recoverCellsAndKzgProofs via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: cell_index 128 = CELLS_PER_EXT_BLOB (one past the end). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm vanishing_polynomial_for_missing_cells zeros exactly on the missing columns' cosets (cell_index 128 = CELLS_PER_EXT_BLOB (one past the end)).
- Invariant to test: Z(x) roots == the missing columns' evaluation points, nothing more or less.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: Z(x) roots == the missing columns' evaluation points, nothing more or less (input: cell_index 128 = CELLS_PER_EXT_BLOB (one past the end)).
