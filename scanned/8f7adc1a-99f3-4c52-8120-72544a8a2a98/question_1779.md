# Q1779: VerifyBlobKZGProofBatch - empty batch returns true via Go [a-64-item-batch-with-exactly-one-crafted]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyBlobKZGProofBatch (used by Geth/Erigon/Prysm)` with a 64-item batch with exactly one crafted entry, make c-kzg-4844 break the invariant that verify(...,0) == the reference verdict for an empty batch (vacuously true, never hiding a real item) so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_blob_kzg_proof_batch)
- Entrypoint: bindings/go ckzg4844.VerifyBlobKZGProofBatch (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: a 64-item batch with exactly one crafted entry. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: call the batch verifier with n==0 and check the true short-circuit matches the reference and cannot mask a required check (a 64-item batch with exactly one crafted entry).
- Invariant to test: verify(...,0) == the reference verdict for an empty batch (vacuously true, never hiding a real item).
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: verify(...,0) == the reference verdict for an empty batch (vacuously true, never hiding a real item) (input: a 64-item batch with exactly one crafted entry).
