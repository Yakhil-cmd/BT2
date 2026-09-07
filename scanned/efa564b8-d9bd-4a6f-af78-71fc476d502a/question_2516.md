# Q2516: verify_blob_kzg_proof - infinity proof for a blob via Python [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_blob_kzg_proof via ckzg_wrap.c (spec / tooling clients)` with the G1 generator point, make c-kzg-4844 break the invariant that *ok true iff the pairing holds; infinity proof must not verify so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/python ckzg.verify_blob_kzg_proof via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass an infinity proof against a real blob/commitment (the G1 generator point).
- Invariant to test: *ok true iff the pairing holds; infinity proof must not verify.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: *ok true iff the pairing holds; infinity proof must not verify (input: the G1 generator point).
