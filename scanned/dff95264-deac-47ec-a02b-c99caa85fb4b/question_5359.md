# Q5359: compute_blob_kzg_proof - non-canonical commitment argument via C [a-point-whose-compression-is-accepted-by]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with a point whose compression is accepted by blst_p1_uncompress but is not in G1, make c-kzg-4844 break the invariant that the commitment used == the canonical validated point, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_blob_kzg_proof (helper: bytes_to_kzg_commitment)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: a point whose compression is accepted by blst_p1_uncompress but is not in G1. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a non-canonical/inf commitment and confirm bytes_to_kzg_commitment gates it before compute_challenge (a point whose compression is accepted by blst_p1_uncompress but is not in G1).
- Invariant to test: the commitment used == the canonical validated point, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: the commitment used == the canonical validated point, else C_KZG_BADARGS (input: a point whose compression is accepted by blst_p1_uncompress but is not in G1).
