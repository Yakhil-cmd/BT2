# Q5628: verify_kzg_proof - accept an infinity commitment via Python [two-distinct-byte-strings-a-client-belie]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_kzg_proof via ckzg_wrap.c (spec / tooling clients)` with two distinct byte strings a client believes encode the same commitment, make c-kzg-4844 break the invariant that *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: bindings/python ckzg.verify_kzg_proof via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: two distinct byte strings a client believes encode the same commitment. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment (validate_kzg_g1 accepts it before the subgroup check) with a matching chosen y and proof (two distinct byte strings a client believes encode the same commitment).
- Invariant to test: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C (input: two distinct byte strings a client believes encode the same commitment).
