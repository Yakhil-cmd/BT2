# Q5841: verify_blob_kzg_proof_batch - infinity commitment inside a batch via Elixir [two-distinct-byte-strings-a-client-belie]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.verify_blob_kzg_proof_batch via ckzg_wrap.c NIF` with two distinct byte strings a client believes encode the same commitment, make c-kzg-4844 break the invariant that batch true iff every triple's pairing holds, infinity commitment included so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_kzg_proof_batch)
- Entrypoint: bindings/elixir KZG.verify_blob_kzg_proof_batch via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: two distinct byte strings a client believes encode the same commitment. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a triple whose commitment is the point at infinity and see if aggregation accepts it (two distinct byte strings a client believes encode the same commitment).
- Invariant to test: batch true iff every triple's pairing holds, infinity commitment included.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: batch true iff every triple's pairing holds, infinity commitment included (input: two distinct byte strings a client believes encode the same commitment).
