# Q3939: blob_to_kzg_commitment - identity-point encoding of a commitment via Python [recovery-from-65-cells-one-recoverable-c]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.blob_to_kzg_commitment via ckzg_wrap.c (spec / tooling clients)` with recovery from 65 cells (one recoverable column), make c-kzg-4844 break the invariant that the 48 output bytes == the spec's compressed identity encoding, matching other clients so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: blob_to_kzg_commitment (helper: bytes_from_g1)
- Entrypoint: bindings/python ckzg.blob_to_kzg_commitment via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: recovery from 65 cells (one recoverable column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: craft a blob whose commitment is the identity and confirm bytes_from_g1 serializes it exactly as the spec expects (recovery from 65 cells (one recoverable column)).
- Invariant to test: the 48 output bytes == the spec's compressed identity encoding, matching other clients.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: the 48 output bytes == the spec's compressed identity encoding, matching other clients (input: recovery from 65 cells (one recoverable column)).
