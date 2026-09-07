# Q3196: compute_cells - FK20 circulant stride mapping via Python [recovery-from-exactly-cells-per-blob-64]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.compute_cells via ckzg_wrap.c (spec / tooling clients)` with recovery from exactly CELLS_PER_BLOB = 64 cells, make c-kzg-4844 break the invariant that cells derived from x_ext_fft_columns == the reference cells so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: circulant_coeffs_stride)
- Entrypoint: bindings/python ckzg.compute_cells via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: recovery from exactly CELLS_PER_BLOB = 64 cells. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm circulant_coeffs_stride maps blob coefficients into the 2r circulant vector as the paper/spec dictates (recovery from exactly CELLS_PER_BLOB = 64 cells).
- Invariant to test: cells derived from x_ext_fft_columns == the reference cells.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: cells derived from x_ext_fft_columns == the reference cells (input: recovery from exactly CELLS_PER_BLOB = 64 cells).
