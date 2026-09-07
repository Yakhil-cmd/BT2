# Q1433: compute_kzg_proof - canonical y_out serialization via Elixir [r-1-smallest-non-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.compute_kzg_proof via ckzg_wrap.c NIF` with r+1 (smallest non-canonical scalar), make c-kzg-4844 break the invariant that y_out bytes == the canonical big-endian encoding of p(z) so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: bytes_from_bls_field)
- Entrypoint: bindings/elixir KZG.compute_kzg_proof via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: r+1 (smallest non-canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm bytes_from_bls_field emits the canonical y for boundary field values (r+1 (smallest non-canonical scalar)).
- Invariant to test: y_out bytes == the canonical big-endian encoding of p(z).
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: y_out bytes == the canonical big-endian encoding of p(z) (input: r+1 (smallest non-canonical scalar)).
