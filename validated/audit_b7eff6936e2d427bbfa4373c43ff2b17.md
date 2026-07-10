### Title
Unconstrained Private Share Contribution in CKD Protocol Allows Malicious Participant to Corrupt Derived Confidential Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In the Confidential Key Derivation (CKD) protocol, each participant computes an ElGamal-encrypted contribution using their private share. There is no constraint — no ZK proof, no pairing check, no commitment binding — verifying that the participant actually used their real private share in the computation. A single malicious participant can substitute any scalar for their private share, and the coordinator blindly sums all contributions, causing all honest parties to accept a corrupted CKD output.

### Finding Description
In `compute_signature_share` (`src/confidential_key_derivation/protocol.rs` lines 148–181), each participant computes:

```rust
let big_s = hash_point * private_share.to_scalar();  // S = x_i * H(pk, app_id)
let big_c = big_s + app_pk * y.0;                    // C = S + y * app_pk
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
Ok((norm_big_y, norm_big_c))
``` [1](#0-0) 

The coordinator in `do_ckd_coordinator` (lines 44–57) simply sums all received contributions without any verification:

```rust
for (_, participant_output) in
    recv_

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L168-181)
```rust
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```
