# Q3018: computeKzgProof - fr_batch_inv on a zero denominator via Zig [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.computeKzgProof via root.zig` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that no proof is returned when any inversion input is zero; out is never used after a BADARGS so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: fr_batch_inv)
- Entrypoint: bindings/zig Settings.computeKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: craft inputs so a denominator (w_i - z) is zero and check fr_batch_inv returns C_KZG_BADARGS without emitting a bogus proof (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: no proof is returned when any inversion input is zero; out is never used after a BADARGS.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: no proof is returned when any inversion input is zero; out is never used after a BADARGS (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
