# Q47: verify_kzg_proof - y at the modulus boundary via Python [the-value-equal-to-the-bls-modulus-r-0x7]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_kzg_proof via ckzg_wrap.c (spec / tooling clients)` with the value equal to the BLS modulus r (0x7300, make c-kzg-4844 break the invariant that *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/python ckzg.verify_kzg_proof via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe y exactly at r and r-1 to find an off-by-one in the canonical check (the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
- Invariant to test: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec (input: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
