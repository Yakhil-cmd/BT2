# Q4773: computeCells - bit-reversal ordering of cells via Nim [recovery-from-127-cells-a-single-missing]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.computeCells (used by Nimbus)` with recovery from 127 cells (a single missing column), make c-kzg-4844 break the invariant that cell k bytes == the reference cell k for the blob so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: bit_reversal_permutation)
- Entrypoint: bindings/nim kzg.computeCells (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: recovery from 127 cells (a single missing column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm bit_reversal_permutation orders the 8192 data points into cells exactly as the spec (recovery from 127 cells (a single missing column)).
- Invariant to test: cell k bytes == the reference cell k for the blob.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: cell k bytes == the reference cell k for the blob (input: recovery from 127 cells (a single missing column)).
