# Q4363: verifyCellKzgProofBatch - deduplicate_commitments compares bytes not points via Nim [an-all-zero-48-byte-string-with-every-fl]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with an all-zero 48-byte string with every flag clear, make c-kzg-4844 break the invariant that commitments dedupe iff they are the same group element, matching the reference so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: deduplicate_commitments)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: an all-zero 48-byte string with every flag clear. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply two commitment encodings a client thinks are equal/unequal and see if deduplicate_commitments splits or merges them wrongly (an all-zero 48-byte string with every flag clear).
- Invariant to test: commitments dedupe iff they are the same group element, matching the reference.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: commitments dedupe iff they are the same group element, matching the reference (input: an all-zero 48-byte string with every flag clear).
