# Q3860: computeCellsAndKzgProofs - FK20 stride/Toeplitz mapping via Nim [recovery-from-65-cells-one-recoverable-c]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.computeCellsAndKzgProofs (used by Nimbus)` with recovery from 65 cells (one recoverable column), make c-kzg-4844 break the invariant that each cell proof == the reference FK20 proof for that column so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: compute_fk20_cell_proofs)
- Entrypoint: bindings/nim kzg.computeCellsAndKzgProofs (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: recovery from 65 cells (one recoverable column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: verify circulant_coeffs_stride and x_ext_fft_columns produce spec-correct multi-proofs (recovery from 65 cells (one recoverable column)).
- Invariant to test: each cell proof == the reference FK20 proof for that column.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: each cell proof == the reference FK20 proof for that column (input: recovery from 65 cells (one recoverable column)).
