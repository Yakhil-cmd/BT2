# Q2989: compute_kzg_proof - proof from the in-domain (m != 0) branch of compute_kzg_proof_impl via Elixir [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.compute_kzg_proof via ckzg_wrap.c NIF` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that the proof for an in-domain z == the proof the barycentric branch would produce for the same polynomial so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: compute_kzg_proof_impl)
- Entrypoint: bindings/elixir KZG.compute_kzg_proof via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: choose z equal to a root of unity so the m!=0 branch rebuilds q_poly from z*(z-w_i) denominators and check it equals the out-of-domain result (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: the proof for an in-domain z == the proof the barycentric branch would produce for the same polynomial.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: the proof for an in-domain z == the proof the barycentric branch would produce for the same polynomial (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
