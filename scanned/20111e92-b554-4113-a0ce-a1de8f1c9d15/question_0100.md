# Q100: verify_blob_kzg_proof - infinity commitment for a blob via Elixir [the-compressed-point-at-infinity-0xc0-th]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.verify_blob_kzg_proof via ckzg_wrap.c NIF` with the compressed point at infinity (0xc0 then 47 zero bytes), make c-kzg-4844 break the invariant that *ok true iff the infinity commitment truly commits to the blob polynomial so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: bindings/elixir KZG.verify_blob_kzg_proof via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: the compressed point at infinity (0xc0 then 47 zero bytes). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment for a chosen blob and see whether the derived (challenge,y) still verifies (the compressed point at infinity (0xc0 then 47 zero bytes)).
- Invariant to test: *ok true iff the infinity commitment truly commits to the blob polynomial.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: *ok true iff the infinity commitment truly commits to the blob polynomial (input: the compressed point at infinity (0xc0 then 47 zero bytes)).
