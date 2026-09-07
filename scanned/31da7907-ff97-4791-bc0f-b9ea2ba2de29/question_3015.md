# Q3015: computeKzgProof - fr_batch_inv on a zero denominator via NodeJs [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.computeKzgProof via kzg.cxx (used by Lodestar)` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that no proof is returned when any inversion input is zero; out is never used after a BADARGS so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: fr_batch_inv)
- Entrypoint: bindings/node.js kzg.computeKzgProof via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: craft inputs so a denominator (w_i - z) is zero and check fr_batch_inv returns C_KZG_BADARGS without emitting a bogus proof (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: no proof is returned when any inversion input is zero; out is never used after a BADARGS.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: no proof is returned when any inversion input is zero; out is never used after a BADARGS (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
