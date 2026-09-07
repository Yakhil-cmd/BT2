# Q5700: verifyKzgProof - chosen y paired with an infinity commitment via Zig [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyKzgProof via root.zig` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that an infinity commitment cannot verify an attacker-chosen (z,y) unless it truly commits to that poly so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/zig Settings.verifyKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: set commitment to infinity and pick y so [y]G1 cancels, forging p(z)=y (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: an infinity commitment cannot verify an attacker-chosen (z,y) unless it truly commits to that poly.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: an infinity commitment cannot verify an attacker-chosen (z,y) unless it truly commits to that poly (input: 2^256 - r (wraps to a small residue if reduced without the check)).
