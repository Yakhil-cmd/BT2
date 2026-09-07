# Q909: verifyBlobKzgProof - infinity proof for a blob via NodeJs [a-48-byte-string-with-the-infinity-flag]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyBlobKzgProof via kzg.cxx (used by Lodestar)` with a 48-byte string with the infinity flag set but a nonzero x coordinate, make c-kzg-4844 break the invariant that *ok true iff the pairing holds; infinity proof must not verify so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/node.js kzg.verifyBlobKzgProof via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: a 48-byte string with the infinity flag set but a nonzero x coordinate. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass an infinity proof against a real blob/commitment (a 48-byte string with the infinity flag set but a nonzero x coordinate).
- Invariant to test: *ok true iff the pairing holds; infinity proof must not verify.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: *ok true iff the pairing holds; infinity proof must not verify (input: a 48-byte string with the infinity flag set but a nonzero x coordinate).
