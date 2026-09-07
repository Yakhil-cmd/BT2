# Q4: verifyKzgProof - accept an infinity commitment via Java [the-compressed-point-at-infinity-0xc0-th]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.verifyKzgProof via ckzg_jni.c (used by Besu/Teku)` with the compressed point at infinity (0xc0 then 47 zero bytes), make c-kzg-4844 break the invariant that *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: bindings/java CKZG4844JNI.verifyKzgProof via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: the compressed point at infinity (0xc0 then 47 zero bytes). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment (validate_kzg_g1 accepts it before the subgroup check) with a matching chosen y and proof (the compressed point at infinity (0xc0 then 47 zero bytes)).
- Invariant to test: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C (input: the compressed point at infinity (0xc0 then 47 zero bytes)).
