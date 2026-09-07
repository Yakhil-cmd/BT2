# Q5046: verifyBlobKzgProofBatch - infinity proof inside a batch via Nim [a-point-whose-compression-is-accepted-by]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus)` with a point whose compression is accepted by blst_p1_uncompress but is not in G1, make c-kzg-4844 break the invariant that batch true iff every proof genuinely opens its claim so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: g1_lincomb_naive)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a point whose compression is accepted by blst_p1_uncompress but is not in G1. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a triple whose proof is infinity; g1_lincomb_naive still weights it (a point whose compression is accepted by blst_p1_uncompress but is not in G1).
- Invariant to test: batch true iff every proof genuinely opens its claim.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: batch true iff every proof genuinely opens its claim (input: a point whose compression is accepted by blst_p1_uncompress but is not in G1).
