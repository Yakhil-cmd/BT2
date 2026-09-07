# Q2156: compute_blob_kzg_proof - non-canonical commitment argument via Elixir [an-on-curve-point-outside-the-order-r-g1]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.compute_blob_kzg_proof via ckzg_wrap.c NIF` with an on-curve point outside the order-r G1 subgroup, make c-kzg-4844 break the invariant that the commitment used == the canonical validated point, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_blob_kzg_proof (helper: bytes_to_kzg_commitment)
- Entrypoint: bindings/elixir KZG.compute_blob_kzg_proof via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: an on-curve point outside the order-r G1 subgroup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a non-canonical/inf commitment and confirm bytes_to_kzg_commitment gates it before compute_challenge (an on-curve point outside the order-r G1 subgroup).
- Invariant to test: the commitment used == the canonical validated point, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: the commitment used == the canonical validated point, else C_KZG_BADARGS (input: an on-curve point outside the order-r G1 subgroup).
