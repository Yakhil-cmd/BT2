# Q5574: computeCells - bit-reversal ordering of cells via NodeJs [a-blob-with-a-single-nonzero-coefficient]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.computeCells via kzg.cxx (used by Lodestar)` with a blob with a single nonzero coefficient at index 4095, make c-kzg-4844 break the invariant that cell k bytes == the reference cell k for the blob so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: bit_reversal_permutation)
- Entrypoint: bindings/node.js kzg.computeCells via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: a blob with a single nonzero coefficient at index 4095. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm bit_reversal_permutation orders the 8192 data points into cells exactly as the spec (a blob with a single nonzero coefficient at index 4095).
- Invariant to test: cell k bytes == the reference cell k for the blob.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: cell k bytes == the reference cell k for the blob (input: a blob with a single nonzero coefficient at index 4095).
