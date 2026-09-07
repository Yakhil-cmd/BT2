# Q34: verifyKzgProof - non-canonical z accepted via Java [the-value-equal-to-the-bls-modulus-r-0x7]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyKzgProof via ckzg_jni.c (used by Besu/Teku)` with the value equal to the BLS modulus r (0x7300, make c-kzg-4844 break the invariant that z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/java CKZG4844JNI.verifyKzgProof via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply a z above the modulus and confirm bytes_to_bls_field rejects before pairing (the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
- Invariant to test: z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false (input: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
