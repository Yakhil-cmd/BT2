# Q5116: verifyCellKzgProofBatch - empty cell batch returns true via Nim [a-128-cell-batch-all-mapped-to-one-colum]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with a 128-cell batch all mapped to one column, make c-kzg-4844 break the invariant that verify(...,0) == the reference empty verdict and never hides a required check so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: verify_cell_kzg_proof_batch)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a 128-cell batch all mapped to one column. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: call with num_cells==0 and confirm the true short-circuit matches the reference (a 128-cell batch all mapped to one column).
- Invariant to test: verify(...,0) == the reference empty verdict and never hides a required check.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: verify(...,0) == the reference empty verdict and never hides a required check (input: a 128-cell batch all mapped to one column).
