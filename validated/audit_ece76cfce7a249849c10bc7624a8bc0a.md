The key point: `bytes_to_bls_field` is called on `z_bytes` in `compute_kzg_proof` before `compute_kzg_proof_impl` and `fr_batch_inv` are ever reached, so a value in `[r, 2^256)` never reaches the inversion loop as a raw fr_t.

Let's verify `bytes_to_bls_field`'s canonical-range check.