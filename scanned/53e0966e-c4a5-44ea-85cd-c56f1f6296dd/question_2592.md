# Q2592: VerifyBlobKZGProofBatch - n==1 short-circuit divergence via Go [a-single-item-batch-n-1]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyBlobKZGProofBatch (used by Geth/Erigon/Prysm)` with a single-item batch (n == 1), make c-kzg-4844 break the invariant that verify(...,1) == verify_blob_kzg_proof(same triple); the two paths never disagree so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_blob_kzg_proof_batch)
- Entrypoint: bindings/go ckzg4844.VerifyBlobKZGProofBatch (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: a single-item batch (n == 1). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: compare the n==1 path (delegates to verify_blob_kzg_proof) against the n>1 aggregation path on the same triple (a single-item batch (n == 1)).
- Invariant to test: verify(...,1) == verify_blob_kzg_proof(same triple); the two paths never disagree.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: verify(...,1) == verify_blob_kzg_proof(same triple); the two paths never disagree (input: a single-item batch (n == 1)).
