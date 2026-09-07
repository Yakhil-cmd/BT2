# Q4798: ComputeCells - FK20 circulant stride mapping via Go [recovery-from-127-cells-a-single-missing]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.ComputeCells (used by Geth/Erigon/Prysm)` with recovery from 127 cells (a single missing column), make c-kzg-4844 break the invariant that cells derived from x_ext_fft_columns == the reference cells so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: circulant_coeffs_stride)
- Entrypoint: bindings/go ckzg4844.ComputeCells (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: recovery from 127 cells (a single missing column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm circulant_coeffs_stride maps blob coefficients into the 2r circulant vector as the paper/spec dictates (recovery from 127 cells (a single missing column)).
- Invariant to test: cells derived from x_ext_fft_columns == the reference cells.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: cells derived from x_ext_fft_columns == the reference cells (input: recovery from 127 cells (a single missing column)).
