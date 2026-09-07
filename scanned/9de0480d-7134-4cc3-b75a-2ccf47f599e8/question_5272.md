# Q5272: recoverCellsAndKzgProofs - strict-ascending index check via Java [cell-index-128-cells-per-ext-blob-one-pa]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.recoverCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku)` with cell_index 128 = CELLS_PER_EXT_BLOB (one past the end), make c-kzg-4844 break the invariant that recovery rejects non-ascending/duplicate indices before touching recovered_cells_fr so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip7594/eip7594.c :: recover_cells_and_kzg_proofs (helper: recover_cells_and_kzg_proofs)
- Entrypoint: bindings/java CKZG4844JNI.recoverCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: cell_index 128 = CELLS_PER_EXT_BLOB (one past the end). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: submit indices that are not strictly ascending and confirm the C_KZG_BADARGS guard fires before any write (cell_index 128 = CELLS_PER_EXT_BLOB (one past the end)).
- Invariant to test: recovery rejects non-ascending/duplicate indices before touching recovered_cells_fr.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: recovery rejects non-ascending/duplicate indices before touching recovered_cells_fr (input: cell_index 128 = CELLS_PER_EXT_BLOB (one past the end)).
