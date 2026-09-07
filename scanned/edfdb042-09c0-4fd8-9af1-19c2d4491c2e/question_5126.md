# Q5126: verifyCellKzgProofBatch - num_cells not upper-bounded via Nim [a-128-cell-batch-all-mapped-to-one-colum]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with a 128-cell batch all mapped to one column, make c-kzg-4844 break the invariant that allocation size == exact transcript length; num_cells has a spec bound and no multiply wraps so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: compute_verify_cell_kzg_proof_batch_challenge)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a 128-cell batch all mapped to one column. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a num_cells far above CELLS_PER_EXT_BLOB and drive the input_size / calloc arithmetic in the challenge toward overflow (a 128-cell batch all mapped to one column).
- Invariant to test: allocation size == exact transcript length; num_cells has a spec bound and no multiply wraps.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: allocation size == exact transcript length; num_cells has a spec bound and no multiply wraps (input: a 128-cell batch all mapped to one column).
