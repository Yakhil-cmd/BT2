# Q3229: verify_kzg_proof - accept an infinity proof via Python [a-compressed-point-with-the-sign-y-bit-f]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_kzg_proof via ckzg_wrap.c (spec / tooling clients)` with a compressed point with the sign/y-bit flipped, make c-kzg-4844 break the invariant that *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/python ckzg.verify_kzg_proof via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: a compressed point with the sign/y-bit flipped. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the proof and a y/z that makes the pairing trivially balance (a compressed point with the sign/y-bit flipped).
- Invariant to test: *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: *ok == true iff the pairing relation holds; an infinity proof must not verify a false claim (input: a compressed point with the sign/y-bit flipped).
