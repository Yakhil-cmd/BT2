# Q5815: verifyBlobKzgProofBatch - batch cancellation of an invalid triple via Java [a-batch-mixing-a-valid-entry-with-one-wh]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyBlobKzgProofBatch via ckzg_jni.c (used by Besu/Teku)` with a batch mixing a valid entry with one whose proof is the point at infinity, make c-kzg-4844 break the invariant that batch verdict == AND of the per-triple verdicts; no linear combination cancels a forgery so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_kzg_proof_batch)
- Entrypoint: bindings/java CKZG4844JNI.verifyBlobKzgProofBatch via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: a batch mixing a valid entry with one whose proof is the point at infinity. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: craft two triples whose r-weighted contributions cancel so a forged triple passes inside the batch (a batch mixing a valid entry with one whose proof is the point at infinity).
- Invariant to test: batch verdict == AND of the per-triple verdicts; no linear combination cancels a forgery.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: batch verdict == AND of the per-triple verdicts; no linear combination cancels a forgery (input: a batch mixing a valid entry with one whose proof is the point at infinity).
