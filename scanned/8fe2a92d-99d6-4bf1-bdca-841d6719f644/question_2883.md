# Q2883: recoverCellsAndKzgProofs - minimum-cells boundary via Java [recovery-from-exactly-cells-per-blob-64]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.recoverCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku)` with recovery from exactly CELLS_PER_BLOB = 64 cells, make c-kzg-4844 break the invariant that recovery proceeds iff num_cells >= CELLS_PER_BLOB, matching the reference so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: recover_cells_and_kzg_proofs (helper: recover_cells_and_kzg_proofs)
- Entrypoint: bindings/java CKZG4844JNI.recoverCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: recovery from exactly CELLS_PER_BLOB = 64 cells. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: call with exactly 63 (too few) and exactly 64 cells and confirm the boundary guard is exact (recovery from exactly CELLS_PER_BLOB = 64 cells).
- Invariant to test: recovery proceeds iff num_cells >= CELLS_PER_BLOB, matching the reference.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: recovery proceeds iff num_cells >= CELLS_PER_BLOB, matching the reference (input: recovery from exactly CELLS_PER_BLOB = 64 cells).
