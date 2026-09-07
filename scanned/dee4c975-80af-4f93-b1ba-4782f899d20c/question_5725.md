# Q5725: verifyBlobKzgProof - infinity proof for a blob via Java [two-distinct-byte-strings-a-client-belie]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyBlobKzgProof via ckzg_jni.c (used by Besu/Teku)` with two distinct byte strings a client believes encode the same commitment, make c-kzg-4844 break the invariant that *ok true iff the pairing holds; infinity proof must not verify so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/java CKZG4844JNI.verifyBlobKzgProof via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: two distinct byte strings a client believes encode the same commitment. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass an infinity proof against a real blob/commitment (two distinct byte strings a client believes encode the same commitment).
- Invariant to test: *ok true iff the pairing holds; infinity proof must not verify.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: *ok true iff the pairing holds; infinity proof must not verify (input: two distinct byte strings a client believes encode the same commitment).
