# Q4680: ComputeCellsAndKzgProofs - cells+proofs match the reference via CSharp [recovery-from-127-cells-a-single-missing]

## Question
Can an unprivileged attacker, calling `bindings/csharp Ckzg.ComputeCellsAndKzgProofs via ckzg_wrap.c (used by Nethermind)` with recovery from 127 cells (a single missing column), make c-kzg-4844 break the invariant that (cells,proofs) bytes == the reference output for every blob so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: compute_fk20_cell_proofs)
- Entrypoint: bindings/csharp Ckzg.ComputeCellsAndKzgProofs via ckzg_wrap.c (used by Nethermind); the wrapper casts an int `numCells` to UInt64 and maps C_KZG_BADARGS to an ArgumentException
- Attacker controls: attacker-published bytes: recovery from 127 cells (a single missing column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: differentially compare against Rust-Eth-KZG for random blobs (recovery from 127 cells (a single missing column)).
- Invariant to test: (cells,proofs) bytes == the reference output for every blob.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: an xUnit case in bindings/csharp Ckzg.Test/ReferenceTests.cs asserting the invariant holds: (cells,proofs) bytes == the reference output for every blob (input: recovery from 127 cells (a single missing column)).
