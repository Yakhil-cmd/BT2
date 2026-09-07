# Q3193: computeCells - FK20 circulant stride mapping via Java [recovery-from-exactly-cells-per-blob-64]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.computeCells via ckzg_jni.c (used by Besu/Teku)` with recovery from exactly CELLS_PER_BLOB = 64 cells, make c-kzg-4844 break the invariant that cells derived from x_ext_fft_columns == the reference cells so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: circulant_coeffs_stride)
- Entrypoint: bindings/java CKZG4844JNI.computeCells via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: recovery from exactly CELLS_PER_BLOB = 64 cells. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm circulant_coeffs_stride maps blob coefficients into the 2r circulant vector as the paper/spec dictates (recovery from exactly CELLS_PER_BLOB = 64 cells).
- Invariant to test: cells derived from x_ext_fft_columns == the reference cells.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: cells derived from x_ext_fft_columns == the reference cells (input: recovery from exactly CELLS_PER_BLOB = 64 cells).
