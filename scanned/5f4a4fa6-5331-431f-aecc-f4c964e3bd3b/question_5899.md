# Q5899: verifyBlobKzgProofBatch - batch equals per-item single verify via Nim [a-batch-mixing-a-valid-entry-with-one-wh]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus)` with a batch mixing a valid entry with one whose proof is the point at infinity, make c-kzg-4844 break the invariant that batch verdict == AND of verify_blob_kzg_proof over the same triples, for every n so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_kzg_proof_batch)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a batch mixing a valid entry with one whose proof is the point at infinity. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: verify each triple alone and as a batch and require identical verdicts (a batch mixing a valid entry with one whose proof is the point at infinity).
- Invariant to test: batch verdict == AND of verify_blob_kzg_proof over the same triples, for every n.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: batch verdict == AND of verify_blob_kzg_proof over the same triples, for every n (input: a batch mixing a valid entry with one whose proof is the point at infinity).
