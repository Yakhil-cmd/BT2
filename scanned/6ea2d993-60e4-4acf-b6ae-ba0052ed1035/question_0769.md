# Q769: computeCells - cells match the reference implementation via Zig [precompute-0-versus-precompute-8-loaded]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.computeCells via root.zig` with precompute=0 versus precompute=8 loaded from the same setup, make c-kzg-4844 break the invariant that cell bytes == the reference DAS cells for every blob so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: fr_fft)
- Entrypoint: bindings/zig Settings.computeCells via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: precompute=0 versus precompute=8 loaded from the same setup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: differentially compare computeCells output against Rust-Eth-KZG for random blobs (precompute=0 versus precompute=8 loaded from the same setup).
- Invariant to test: cell bytes == the reference DAS cells for every blob.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: cell bytes == the reference DAS cells for every blob (input: precompute=0 versus precompute=8 loaded from the same setup).
