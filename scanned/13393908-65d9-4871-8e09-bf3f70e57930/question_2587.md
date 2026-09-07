# Q2587: verifyBlobKzgProofBatch - empty batch returns true via Nim [a-single-item-batch-n-1]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus)` with a single-item batch (n == 1), make c-kzg-4844 break the invariant that verify(...,0) == the reference verdict for an empty batch (vacuously true, never hiding a real item) so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_blob_kzg_proof_batch)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a single-item batch (n == 1). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: call the batch verifier with n==0 and check the true short-circuit matches the reference and cannot mask a required check (a single-item batch (n == 1)).
- Invariant to test: verify(...,0) == the reference verdict for an empty batch (vacuously true, never hiding a real item).
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: verify(...,0) == the reference verdict for an empty batch (vacuously true, never hiding a real item) (input: a single-item batch (n == 1)).
