# Q5681: verify_kzg_proof - z at the modulus boundary via Elixir [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.verify_kzg_proof via ckzg_wrap.c NIF` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that z accepted iff canonical; verdict matches the reference at the boundary so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/elixir KZG.verify_kzg_proof via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe z exactly at r and r-1 for a canonical-check off-by-one (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: z accepted iff canonical; verdict matches the reference at the boundary.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: z accepted iff canonical; verdict matches the reference at the boundary (input: 2^256 - r (wraps to a small residue if reduced without the check)).
