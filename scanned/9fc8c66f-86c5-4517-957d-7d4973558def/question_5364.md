# Q5364: computeBlobKzgProof - non-canonical commitment argument via NodeJs [a-point-whose-compression-is-accepted-by]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.computeBlobKzgProof via kzg.cxx (used by Lodestar)` with a point whose compression is accepted by blst_p1_uncompress but is not in G1, make c-kzg-4844 break the invariant that the commitment used == the canonical validated point, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_blob_kzg_proof (helper: bytes_to_kzg_commitment)
- Entrypoint: bindings/node.js kzg.computeBlobKzgProof via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: a point whose compression is accepted by blst_p1_uncompress but is not in G1. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a non-canonical/inf commitment and confirm bytes_to_kzg_commitment gates it before compute_challenge (a point whose compression is accepted by blst_p1_uncompress but is not in G1).
- Invariant to test: the commitment used == the canonical validated point, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: the commitment used == the canonical validated point, else C_KZG_BADARGS (input: a point whose compression is accepted by blst_p1_uncompress but is not in G1).
