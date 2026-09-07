# Q2316: blob_to_kzg_commitment - commitment from a non-canonical blob element via Elixir [r-1-largest-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.blob_to_kzg_commitment via ckzg_wrap.c NIF` with r-1 (largest canonical scalar), make c-kzg-4844 break the invariant that every field element committed == the canonical decode of the blob bytes, or the call returns C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: blob_to_kzg_commitment (helper: blob_to_polynomial)
- Entrypoint: bindings/elixir KZG.blob_to_kzg_commitment via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: r-1 (largest canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: put a non-canonical 32-byte field element in the blob and check blob_to_polynomial/bytes_to_bls_field rejects it before poly_to_kzg_commitment runs (r-1 (largest canonical scalar)).
- Invariant to test: every field element committed == the canonical decode of the blob bytes, or the call returns C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: every field element committed == the canonical decode of the blob bytes, or the call returns C_KZG_BADARGS (input: r-1 (largest canonical scalar)).
