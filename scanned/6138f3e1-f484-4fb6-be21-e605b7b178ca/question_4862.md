# Q4862: verifyKzgProof - y at the modulus boundary via Java [a-value-that-is-canonical-little-endian]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyKzgProof via ckzg_jni.c (used by Besu/Teku)` with a value that is canonical little-endian but non-canonical big-endian, make c-kzg-4844 break the invariant that *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/java CKZG4844JNI.verifyKzgProof via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: a value that is canonical little-endian but non-canonical big-endian. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe y exactly at r and r-1 to find an off-by-one in the canonical check (a value that is canonical little-endian but non-canonical big-endian).
- Invariant to test: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec (input: a value that is canonical little-endian but non-canonical big-endian).
