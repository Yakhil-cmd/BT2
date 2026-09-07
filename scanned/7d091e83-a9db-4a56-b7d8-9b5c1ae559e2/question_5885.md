# Q5885: verifyBlobKzgProofBatch - large-n allocation/size arithmetic via Java [a-batch-mixing-a-valid-entry-with-one-wh]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyBlobKzgProofBatch via ckzg_jni.c (used by Besu/Teku)` with a batch mixing a valid entry with one whose proof is the point at infinity, make c-kzg-4844 break the invariant that the malloc size == the exact transcript length; no multiply wraps and no OOB write occurs so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/java CKZG4844JNI.verifyBlobKzgProofBatch via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: a batch mixing a valid entry with one whose proof is the point at infinity. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: drive input_size = DOMAIN + 2*u64 + n*(commit+2*fe+proof) toward size_t overflow (a batch mixing a valid entry with one whose proof is the point at infinity).
- Invariant to test: the malloc size == the exact transcript length; no multiply wraps and no OOB write occurs.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: the malloc size == the exact transcript length; no multiply wraps and no OOB write occurs (input: a batch mixing a valid entry with one whose proof is the point at infinity).
