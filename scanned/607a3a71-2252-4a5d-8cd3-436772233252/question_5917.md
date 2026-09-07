# Q5917: verifyCellKzgProofBatch - empty cell batch returns true via NodeJs [a-batch-mixing-a-valid-entry-with-one-wh]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar)` with a batch mixing a valid entry with one whose proof is the point at infinity, make c-kzg-4844 break the invariant that verify(...,0) == the reference empty verdict and never hides a required check so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: verify_cell_kzg_proof_batch)
- Entrypoint: bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: a batch mixing a valid entry with one whose proof is the point at infinity. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: call with num_cells==0 and confirm the true short-circuit matches the reference (a batch mixing a valid entry with one whose proof is the point at infinity).
- Invariant to test: verify(...,0) == the reference empty verdict and never hides a required check.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: verify(...,0) == the reference empty verdict and never hides a required check (input: a batch mixing a valid entry with one whose proof is the point at infinity).
