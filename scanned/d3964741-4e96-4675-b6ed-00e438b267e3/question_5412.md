# Q5412: computeKzgProof - y via the evaluation-form shortcut via Java [a-value-that-is-canonical-little-endian]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.computeKzgProof via ckzg_jni.c (used by Besu/Teku)` with a value that is canonical little-endian but non-canonical big-endian, make c-kzg-4844 break the invariant that the returned y == p(z) exactly, including when z lies in the evaluation domain so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: evaluate_polynomial_in_evaluation_form)
- Entrypoint: bindings/java CKZG4844JNI.computeKzgProof via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: a value that is canonical little-endian but non-canonical big-endian. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: hit the fr_equal(x, brp_roots_of_unity[i]) shortcut in evaluate_polynomial_in_evaluation_form and check y == poly[i] (a value that is canonical little-endian but non-canonical big-endian).
- Invariant to test: the returned y == p(z) exactly, including when z lies in the evaluation domain.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: the returned y == p(z) exactly, including when z lies in the evaluation domain (input: a value that is canonical little-endian but non-canonical big-endian).
