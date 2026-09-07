# Q1: verify_kzg_proof - accept an infinity commitment via C [the-compressed-point-at-infinity-0xc0-th]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with the compressed point at infinity (0xc0 then 47 zero bytes), make c-kzg-4844 break the invariant that *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: the compressed point at infinity (0xc0 then 47 zero bytes). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment (validate_kzg_g1 accepts it before the subgroup check) with a matching chosen y and proof (the compressed point at infinity (0xc0 then 47 zero bytes)).
- Invariant to test: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C (input: the compressed point at infinity (0xc0 then 47 zero bytes)).
