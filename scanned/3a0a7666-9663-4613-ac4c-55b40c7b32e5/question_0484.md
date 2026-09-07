# Q484: recoverCellsAndKzgProofs - recovered output matches the reference via Java [precompute-0-versus-precompute-8-loaded]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.recoverCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku)` with precompute=0 versus precompute=8 loaded from the same setup, make c-kzg-4844 break the invariant that recovered (cells,proofs) == the reference recovery for the same inputs so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: recover_cells_and_kzg_proofs (helper: recover_cells)
- Entrypoint: bindings/java CKZG4844JNI.recoverCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: precompute=0 versus precompute=8 loaded from the same setup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: differentially compare recovered cells/proofs against Rust-Eth-KZG (precompute=0 versus precompute=8 loaded from the same setup).
- Invariant to test: recovered (cells,proofs) == the reference recovery for the same inputs.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: recovered (cells,proofs) == the reference recovery for the same inputs (input: precompute=0 versus precompute=8 loaded from the same setup).
