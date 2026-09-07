# Q1401: computeKzgProof - y via the evaluation-form shortcut via Nim [r-1-smallest-non-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.computeKzgProof (used by Nimbus)` with r+1 (smallest non-canonical scalar), make c-kzg-4844 break the invariant that the returned y == p(z) exactly, including when z lies in the evaluation domain so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: evaluate_polynomial_in_evaluation_form)
- Entrypoint: bindings/nim kzg.computeKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: r+1 (smallest non-canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: hit the fr_equal(x, brp_roots_of_unity[i]) shortcut in evaluate_polynomial_in_evaluation_form and check y == poly[i] (r+1 (smallest non-canonical scalar)).
- Invariant to test: the returned y == p(z) exactly, including when z lies in the evaluation domain.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: the returned y == p(z) exactly, including when z lies in the evaluation domain (input: r+1 (smallest non-canonical scalar)).
