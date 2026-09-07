# Q4502: recover_cells_and_kzg_proofs - recovered output matches the reference via Python [recovery-from-127-cells-a-single-missing]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.recover_cells_and_kzg_proofs via ckzg_wrap.c (spec / tooling clients)` with recovery from 127 cells (a single missing column), make c-kzg-4844 break the invariant that recovered (cells,proofs) == the reference recovery for the same inputs so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: recover_cells_and_kzg_proofs (helper: recover_cells)
- Entrypoint: bindings/python ckzg.recover_cells_and_kzg_proofs via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: recovery from 127 cells (a single missing column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: differentially compare recovered cells/proofs against Rust-Eth-KZG (recovery from 127 cells (a single missing column)).
- Invariant to test: recovered (cells,proofs) == the reference recovery for the same inputs.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: recovered (cells,proofs) == the reference recovery for the same inputs (input: recovery from 127 cells (a single missing column)).
