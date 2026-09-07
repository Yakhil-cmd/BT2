# Q3291: verifyKzgProof - chosen y paired with an infinity commitment via Zig [a-value-in-r-2-256-that-blst-scalar-fr-c]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyKzgProof via root.zig` with a value in [r, 2^256) that blst_scalar_fr_check must reject, make c-kzg-4844 break the invariant that an infinity commitment cannot verify an attacker-chosen (z,y) unless it truly commits to that poly so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/zig Settings.verifyKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: a value in [r, 2^256) that blst_scalar_fr_check must reject. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: set commitment to infinity and pick y so [y]G1 cancels, forging p(z)=y (a value in [r, 2^256) that blst_scalar_fr_check must reject).
- Invariant to test: an infinity commitment cannot verify an attacker-chosen (z,y) unless it truly commits to that poly.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: an infinity commitment cannot verify an attacker-chosen (z,y) unless it truly commits to that poly (input: a value in [r, 2^256) that blst_scalar_fr_check must reject).
