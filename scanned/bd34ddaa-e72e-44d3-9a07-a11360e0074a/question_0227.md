# Q227: verify_blob_kzg_proof_batch - infinity proof inside a batch via Python [the-compressed-point-at-infinity-0xc0-th]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_blob_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients)` with the compressed point at infinity (0xc0 then 47 zero bytes), make c-kzg-4844 break the invariant that batch true iff every proof genuinely opens its claim so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: g1_lincomb_naive)
- Entrypoint: bindings/python ckzg.verify_blob_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: the compressed point at infinity (0xc0 then 47 zero bytes). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a triple whose proof is infinity; g1_lincomb_naive still weights it (the compressed point at infinity (0xc0 then 47 zero bytes)).
- Invariant to test: batch true iff every proof genuinely opens its claim.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: batch true iff every proof genuinely opens its claim (input: the compressed point at infinity (0xc0 then 47 zero bytes)).
