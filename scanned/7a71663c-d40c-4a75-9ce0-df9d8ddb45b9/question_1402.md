# Q1402: computeKzgProof - y via the evaluation-form shortcut via Zig [r-1-smallest-non-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.computeKzgProof via root.zig` with r+1 (smallest non-canonical scalar), make c-kzg-4844 break the invariant that the returned y == p(z) exactly, including when z lies in the evaluation domain so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: evaluate_polynomial_in_evaluation_form)
- Entrypoint: bindings/zig Settings.computeKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: r+1 (smallest non-canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: hit the fr_equal(x, brp_roots_of_unity[i]) shortcut in evaluate_polynomial_in_evaluation_form and check y == poly[i] (r+1 (smallest non-canonical scalar)).
- Invariant to test: the returned y == p(z) exactly, including when z lies in the evaluation domain.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: the returned y == p(z) exactly, including when z lies in the evaluation domain (input: r+1 (smallest non-canonical scalar)).
