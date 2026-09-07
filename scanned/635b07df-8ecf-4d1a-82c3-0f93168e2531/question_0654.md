# Q654: computeCellsAndKzgProofs - proof bit-reversal ordering via Java [precompute-0-versus-precompute-8-loaded]

## Question
Can an unprivileged attacker, calling `bindings/java CKZG4844JNI.computeCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku)` with precompute=0 versus precompute=8 loaded from the same setup, make c-kzg-4844 break the invariant that proof k == the reference proof for cell k so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: bit_reversal_permutation)
- Entrypoint: bindings/java CKZG4844JNI.computeCellsAndKzgProofs via ckzg_jni.c (used by Besu/Teku); the JNI layer trusts a jlong `count` cast to size_t and only checks GetArrayLength == count*BYTES_PER_*
- Attacker controls: attacker-published bytes: precompute=0 versus precompute=8 loaded from the same setup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm bit_reversal_permutation on proofs matches cell ordering and the spec (precompute=0 versus precompute=8 loaded from the same setup).
- Invariant to test: proof k == the reference proof for cell k.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a JUnit case in bindings/java CKZG4844JNITest asserting the invariant holds: proof k == the reference proof for cell k (input: precompute=0 versus precompute=8 loaded from the same setup).
