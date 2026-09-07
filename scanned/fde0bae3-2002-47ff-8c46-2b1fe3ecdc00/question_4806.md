# Q4806: verifyCellKzgProofBatch - get_cell_index coerces a non-number index to 0 via NodeJs [an-ascending-list-with-one-column-index]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar)` with an ascending list with one column index repeated later, make c-kzg-4844 break the invariant that the cell_index passed to C == the caller's index or the call aborts; a coerced 0 must not silently mis-map a cell so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: get_cell_index)
- Entrypoint: bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: an ascending list with one column index repeated later. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a NaN / non-number cellIndex; get_cell_index throws a JS exception but returns 0 and the C++ keeps running with index 0 (an ascending list with one column index repeated later).
- Invariant to test: the cell_index passed to C == the caller's index or the call aborts; a coerced 0 must not silently mis-map a cell.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: the cell_index passed to C == the caller's index or the call aborts; a coerced 0 must not silently mis-map a cell (input: an ascending list with one column index repeated later).
