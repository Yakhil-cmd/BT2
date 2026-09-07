# Q1605: verifyCellKzgProofBatch - empty-slice null pointer to C via Zig [a-3-item-batch-containing-two-byte-ident]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyCellKzgProofBatch via root.zig` with a 3-item batch containing two byte-identical entries, make c-kzg-4844 break the invariant that a zero count with null pointers == a defined no-op verdict, never a null deref so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: verifyCellKzgProofBatch)
- Entrypoint: bindings/zig Settings.verifyCellKzgProofBatch via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: a 3-item batch containing two byte-identical entries. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass empty slices so sliceConstPtr yields null and confirm C handles count 0 without dereferencing (a 3-item batch containing two byte-identical entries).
- Invariant to test: a zero count with null pointers == a defined no-op verdict, never a null deref.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: a zero count with null pointers == a defined no-op verdict, never a null deref (input: a 3-item batch containing two byte-identical entries).
