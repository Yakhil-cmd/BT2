# Q3009: compute_kzg_proof - y via the evaluation-form shortcut via Elixir [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/elixir KZG.compute_kzg_proof via ckzg_wrap.c NIF` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that the returned y == p(z) exactly, including when z lies in the evaluation domain so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: evaluate_polynomial_in_evaluation_form)
- Entrypoint: bindings/elixir KZG.compute_kzg_proof via ckzg_wrap.c NIF; the NIF derives counts from enif_get_list_length and fills a fixed-size int loop index
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: hit the fr_equal(x, brp_roots_of_unity[i]) shortcut in evaluate_polynomial_in_evaluation_form and check y == poly[i] (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: the returned y == p(z) exactly, including when z lies in the evaluation domain.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a case in bindings/elixir/test/ckzg_test.exs asserting the invariant holds: the returned y == p(z) exactly, including when z lies in the evaluation domain (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
