# Q574: computeKzgProof - proof from the in-domain (m != 0) branch of compute_kzg_proof_impl via Java [the-value-equal-to-the-bls-modulus-r-0x7]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.computeKzgProof via ckzg_jni.c (used by Besu/Teku)` with the value equal to the BLS modulus r (0x7300, make c-kzg-4844 break the invariant that the proof for an in-domain z == the proof the barycentric branch would produce for the same polynomial so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: compute_kzg_proof_impl)
- Entrypoint: bindings/java CKZG4844JNI.computeKzgProof via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: choose z equal to a root of unity so the m!=0 branch rebuilds q_poly from z*(z-w_i) denominators and check it equals the out-of-domain result (the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
- Invariant to test: the proof for an in-domain z == the proof the barycentric branch would produce for the same polynomial.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: the proof for an in-domain z == the proof the barycentric branch would produce for the same polynomial (input: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
