# Q4602: compute_kzg_proof - proof with a non-canonical z via Python [the-field-element-0-as-32-zero-bytes]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.compute_kzg_proof via ckzg_wrap.c (spec / tooling clients)` with the field element 0 as 32 zero bytes, make c-kzg-4844 break the invariant that z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/python ckzg.compute_kzg_proof via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: the field element 0 as 32 zero bytes. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a z above the modulus and confirm bytes_to_bls_field rejects it before compute_kzg_proof_impl (the field element 0 as 32 zero bytes).
- Invariant to test: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS (input: the field element 0 as 32 zero bytes).
