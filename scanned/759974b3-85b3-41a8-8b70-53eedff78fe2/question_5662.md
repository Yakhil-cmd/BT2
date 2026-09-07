# Q5662: verify_kzg_proof - y at the modulus boundary via C [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe y exactly at r and r-1 to find an off-by-one in the canonical check (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec (input: 2^256 - r (wraps to a small residue if reduced without the check)).
