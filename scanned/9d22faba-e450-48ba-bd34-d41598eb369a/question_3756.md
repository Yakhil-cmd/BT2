# Q3756: computeBlobKzgProof - non-canonical commitment argument via Java [a-compressed-point-with-the-sign-y-bit-f]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.computeBlobKzgProof via ckzg_jni.c (used by Besu/Teku)` with a compressed point with the sign/y-bit flipped, make c-kzg-4844 break the invariant that the commitment used == the canonical validated point, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_blob_kzg_proof (helper: bytes_to_kzg_commitment)
- Entrypoint: bindings/java CKZG4844JNI.computeBlobKzgProof via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: a compressed point with the sign/y-bit flipped. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a non-canonical/inf commitment and confirm bytes_to_kzg_commitment gates it before compute_challenge (a compressed point with the sign/y-bit flipped).
- Invariant to test: the commitment used == the canonical validated point, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: the commitment used == the canonical validated point, else C_KZG_BADARGS (input: a compressed point with the sign/y-bit flipped).
