# Q2613: verifyBlobKzgProofBatch - predictable r via duplicate entries via Java [a-single-item-batch-n-1]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyBlobKzgProofBatch via ckzg_jni.c (used by Besu/Teku)` with a single-item batch (n == 1), make c-kzg-4844 break the invariant that the challenge r binds every entry uniquely; duplicates do not create a cancelling weight so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/java CKZG4844JNI.verifyBlobKzgProofBatch via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: a single-item batch (n == 1). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: submit byte-identical entries so their r-powers coincide and probe for a cancellation the transcript cannot bind (a single-item batch (n == 1)).
- Invariant to test: the challenge r binds every entry uniquely; duplicates do not create a cancelling weight.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: the challenge r binds every entry uniquely; duplicates do not create a cancelling weight (input: a single-item batch (n == 1)).
