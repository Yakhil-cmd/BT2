# Q5802: verify_blob_kzg_proof_batch - n==1 short-circuit divergence via C [a-batch-mixing-a-valid-entry-with-one-wh]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with a batch mixing a valid entry with one whose proof is the point at infinity, make c-kzg-4844 break the invariant that verify(...,1) == verify_blob_kzg_proof(same triple); the two paths never disagree so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_blob_kzg_proof_batch)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: a batch mixing a valid entry with one whose proof is the point at infinity. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: compare the n==1 path (delegates to verify_blob_kzg_proof) against the n>1 aggregation path on the same triple (a batch mixing a valid entry with one whose proof is the point at infinity).
- Invariant to test: verify(...,1) == verify_blob_kzg_proof(same triple); the two paths never disagree.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: verify(...,1) == verify_blob_kzg_proof(same triple); the two paths never disagree (input: a batch mixing a valid entry with one whose proof is the point at infinity).
