# Q5958: verify_cell_kzg_proof_batch - infinity cell proof filtered from the lincomb via Python [two-distinct-byte-strings-a-client-belie]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_cell_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients)` with two distinct byte strings a client believes encode the same commitment, make c-kzg-4844 break the invariant that *ok true iff every proof opens its cell; a filtered infinity proof cannot pass so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: g1_lincomb_fast)
- Entrypoint: bindings/python ckzg.verify_cell_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: two distinct byte strings a client believes encode the same commitment. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a proof that is the point at infinity so g1_lincomb_fast drops it while its r^i weight still scales the commitment side (two distinct byte strings a client believes encode the same commitment).
- Invariant to test: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass (input: two distinct byte strings a client believes encode the same commitment).
