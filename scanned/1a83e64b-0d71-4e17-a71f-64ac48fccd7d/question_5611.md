# Q5611: verifyCellKzgProofBatch - JS double cell index truncates above 2^53 via NodeJs [cell-index-128-cells-per-ext-blob-one-pa]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar)` with cell_index 128 = CELLS_PER_EXT_BLOB (one past the end), make c-kzg-4844 break the invariant that the uint64 index in C == the intended index; precision loss must be rejected so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: get_cell_index)
- Entrypoint: bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: cell_index 128 = CELLS_PER_EXT_BLOB (one past the end). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a cellIndex above 2^53 that loses precision in the double->uint64 cast (cell_index 128 = CELLS_PER_EXT_BLOB (one past the end)).
- Invariant to test: the uint64 index in C == the intended index; precision loss must be rejected.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: the uint64 index in C == the intended index; precision loss must be rejected (input: cell_index 128 = CELLS_PER_EXT_BLOB (one past the end)).
