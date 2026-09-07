# Q341: verify_cell_kzg_proof_batch - deduplicate_commitments compares bytes not points via C [the-compressed-point-at-infinity-0xc0-th]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with the compressed point at infinity (0xc0 then 47 zero bytes), make c-kzg-4844 break the invariant that commitments dedupe iff they are the same group element, matching the reference so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: deduplicate_commitments)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: the compressed point at infinity (0xc0 then 47 zero bytes). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply two commitment encodings a client thinks are equal/unequal and see if deduplicate_commitments splits or merges them wrongly (the compressed point at infinity (0xc0 then 47 zero bytes)).
- Invariant to test: commitments dedupe iff they are the same group element, matching the reference.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: commitments dedupe iff they are the same group element, matching the reference (input: the compressed point at infinity (0xc0 then 47 zero bytes)).
