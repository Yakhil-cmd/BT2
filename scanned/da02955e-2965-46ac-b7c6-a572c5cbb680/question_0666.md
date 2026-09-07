# Q666: computeCellsAndKzgProofs - cells+proofs match the reference via NodeJs [precompute-0-versus-precompute-8-loaded]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.computeCellsAndKzgProofs via kzg.cxx (used by Lodestar)` with precompute=0 versus precompute=8 loaded from the same setup, make c-kzg-4844 break the invariant that (cells,proofs) bytes == the reference output for every blob so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: compute_fk20_cell_proofs)
- Entrypoint: bindings/node.js kzg.computeCellsAndKzgProofs via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: precompute=0 versus precompute=8 loaded from the same setup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: differentially compare against Rust-Eth-KZG for random blobs (precompute=0 versus precompute=8 loaded from the same setup).
- Invariant to test: (cells,proofs) bytes == the reference output for every blob.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: (cells,proofs) bytes == the reference output for every blob (input: precompute=0 versus precompute=8 loaded from the same setup).
