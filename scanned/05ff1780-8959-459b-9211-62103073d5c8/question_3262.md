# Q3262: verify_kzg_proof - y at the modulus boundary via Elixir [a-value-in-r-2-256-that-blst-scalar-fr-c]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.verify_kzg_proof via ckzg_wrap.c NIF` with a value in [r, 2^256) that blst_scalar_fr_check must reject, make c-kzg-4844 break the invariant that *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/elixir KZG.verify_kzg_proof via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: a value in [r, 2^256) that blst_scalar_fr_check must reject. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe y exactly at r and r-1 to find an off-by-one in the canonical check (a value in [r, 2^256) that blst_scalar_fr_check must reject).
- Invariant to test: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec (input: a value in [r, 2^256) that blst_scalar_fr_check must reject).
