# Q3846: computeCellsAndKzgProofs - cells+proofs differ across precompute via Java [recovery-from-65-cells-one-recoverable-c]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.computeCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku)` with recovery from 65 cells (one recoverable column), make c-kzg-4844 break the invariant that proof bytes == the reference cell-proofs for the blob regardless of precompute so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: compute_fk20_cell_proofs)
- Entrypoint: bindings/java CKZG4844JNI.computeCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: recovery from 65 cells (one recoverable column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: compute cells and proofs with precompute 0 vs 8 and require identical bytes (recovery from 65 cells (one recoverable column)).
- Invariant to test: proof bytes == the reference cell-proofs for the blob regardless of precompute.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: proof bytes == the reference cell-proofs for the blob regardless of precompute (input: recovery from 65 cells (one recoverable column)).
