# Q3056: compute_cells_and_kzg_proofs - FK20 stride/Toeplitz mapping via Python [recovery-from-exactly-cells-per-blob-64]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.compute_cells_and_kzg_proofs via ckzg_wrap.c (spec / tooling clients)` with recovery from exactly CELLS_PER_BLOB = 64 cells, make c-kzg-4844 break the invariant that each cell proof == the reference FK20 proof for that column so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: compute_fk20_cell_proofs)
- Entrypoint: bindings/python ckzg.compute_cells_and_kzg_proofs via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: recovery from exactly CELLS_PER_BLOB = 64 cells. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: verify circulant_coeffs_stride and x_ext_fft_columns produce spec-correct multi-proofs (recovery from exactly CELLS_PER_BLOB = 64 cells).
- Invariant to test: each cell proof == the reference FK20 proof for that column.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: each cell proof == the reference FK20 proof for that column (input: recovery from exactly CELLS_PER_BLOB = 64 cells).
