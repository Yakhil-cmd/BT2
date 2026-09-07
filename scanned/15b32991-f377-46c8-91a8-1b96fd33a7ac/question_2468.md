# Q2468: verifyKzgProof - z at the modulus boundary via Zig [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyKzgProof via root.zig` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that z accepted iff canonical; verdict matches the reference at the boundary so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/zig Settings.verifyKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe z exactly at r and r-1 for a canonical-check off-by-one (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: z accepted iff canonical; verdict matches the reference at the boundary.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: z accepted iff canonical; verdict matches the reference at the boundary (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
