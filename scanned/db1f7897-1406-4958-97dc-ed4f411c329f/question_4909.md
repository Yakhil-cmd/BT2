# Q4909: verify_blob_kzg_proof - infinity commitment for a blob via C [a-point-whose-compression-is-accepted-by]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with a point whose compression is accepted by blst_p1_uncompress but is not in G1, make c-kzg-4844 break the invariant that *ok true iff the infinity commitment truly commits to the blob polynomial so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: a point whose compression is accepted by blst_p1_uncompress but is not in G1. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment for a chosen blob and see whether the derived (challenge,y) still verifies (a point whose compression is accepted by blst_p1_uncompress but is not in G1).
- Invariant to test: *ok true iff the infinity commitment truly commits to the blob polynomial.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: *ok true iff the infinity commitment truly commits to the blob polynomial (input: a point whose compression is accepted by blst_p1_uncompress but is not in G1).
