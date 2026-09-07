# Q2898: recoverCellsAndKzgProofs - recovered output matches the reference via Zig [recovery-from-exactly-cells-per-blob-64]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.recoverCellsAndKzgProofs via root.zig` with recovery from exactly CELLS_PER_BLOB = 64 cells, make c-kzg-4844 break the invariant that recovered (cells,proofs) == the reference recovery for the same inputs so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: recover_cells_and_kzg_proofs (helper: recover_cells)
- Entrypoint: bindings/zig Settings.recoverCellsAndKzgProofs via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: recovery from exactly CELLS_PER_BLOB = 64 cells. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: differentially compare recovered cells/proofs against Rust-Eth-KZG (recovery from exactly CELLS_PER_BLOB = 64 cells).
- Invariant to test: recovered (cells,proofs) == the reference recovery for the same inputs.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: recovered (cells,proofs) == the reference recovery for the same inputs (input: recovery from exactly CELLS_PER_BLOB = 64 cells).
