# Q109: verifyBlobKzgProof - infinity proof for a blob via Zig [the-compressed-point-at-infinity-0xc0-th]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyBlobKzgProof via root.zig` with the compressed point at infinity (0xc0 then 47 zero bytes), make c-kzg-4844 break the invariant that *ok true iff the pairing holds; infinity proof must not verify so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/zig Settings.verifyBlobKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: the compressed point at infinity (0xc0 then 47 zero bytes). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass an infinity proof against a real blob/commitment (the compressed point at infinity (0xc0 then 47 zero bytes)).
- Invariant to test: *ok true iff the pairing holds; infinity proof must not verify.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: *ok true iff the pairing holds; infinity proof must not verify (input: the compressed point at infinity (0xc0 then 47 zero bytes)).
