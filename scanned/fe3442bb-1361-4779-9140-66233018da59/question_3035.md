# Q3035: computeKzgProof - canonical y_out serialization via NodeJs [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.computeKzgProof via kzg.cxx (used by Lodestar)` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that y_out bytes == the canonical big-endian encoding of p(z) so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: bytes_from_bls_field)
- Entrypoint: bindings/node.js kzg.computeKzgProof via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm bytes_from_bls_field emits the canonical y for boundary field values (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: y_out bytes == the canonical big-endian encoding of p(z).
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: y_out bytes == the canonical big-endian encoding of p(z) (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
