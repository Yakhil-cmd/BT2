# Q3478: verifyBlobKzgProofBatch - large-n allocation/size arithmetic via NodeJs [an-empty-batch-n-0]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyBlobKzgProofBatch via kzg.cxx (used by Lodestar)` with an empty batch (n == 0), make c-kzg-4844 break the invariant that the malloc size == the exact transcript length; no multiply wraps and no OOB write occurs so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/node.js kzg.verifyBlobKzgProofBatch via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: an empty batch (n == 0). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: drive input_size = DOMAIN + 2*u64 + n*(commit+2*fe+proof) toward size_t overflow (an empty batch (n == 0)).
- Invariant to test: the malloc size == the exact transcript length; no multiply wraps and no OOB write occurs.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: the malloc size == the exact transcript length; no multiply wraps and no OOB write occurs (input: an empty batch (n == 0)).
