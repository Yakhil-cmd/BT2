# Q1137: verifyCellKzgProofBatch - infinity cell proof filtered from the lincomb via Java [a-48-byte-string-with-the-infinity-flag]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyCellKzgProofBatch via ckzg_jni.c (used by Besu/Teku)` with a 48-byte string with the infinity flag set but a nonzero x coordinate, make c-kzg-4844 break the invariant that *ok true iff every proof opens its cell; a filtered infinity proof cannot pass so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: g1_lincomb_fast)
- Entrypoint: bindings/java CKZG4844JNI.verifyCellKzgProofBatch via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: a 48-byte string with the infinity flag set but a nonzero x coordinate. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a proof that is the point at infinity so g1_lincomb_fast drops it while its r^i weight still scales the commitment side (a 48-byte string with the infinity flag set but a nonzero x coordinate).
- Invariant to test: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass (input: a 48-byte string with the infinity flag set but a nonzero x coordinate).
