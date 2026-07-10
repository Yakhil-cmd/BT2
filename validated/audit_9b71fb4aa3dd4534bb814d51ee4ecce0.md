### Title
Unverified Participant Contributions in CKD Aggregation Allow Malicious Participant to Corrupt Derived Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly aggregates `(big_y, big_c)` contributions from every participant with no cryptographic verification that each contribution was honestly computed from the participant's actual private share. A single malicious participant can substitute arbitrary group elements, causing all honest parties to accept a silently corrupted confidential derived key.

---

### Finding Description

The vulnerability class from the reference report is **claimed-vs-actual value mismatch**: a system records the *requested* quantity rather than the *actually received* quantity, breaking downstream logic. The analog here is that the CKD coordinator records the *claimed* cryptographic contribution from each participant rather than verifying it equals the *actual* contribution derived from that participant's private share.

In `do_ckd_coordinator` (lines 35–58 of `src/confidential_key_derivation/protocol.rs`):

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
``` [1](#0-0) 

Each honest participant i is supposed to compute and send:

```
norm_big_y_i = λ_i · y_i · G
norm_big_c_i = λ_i · (x_i · H(pk ‖ app_id) + y_i · app_pk)
```

as shown in `compute_signature_share` (lines 148–181): [2](#0-1) 

The coordinator performs **no verification** that the received `(big_y, big_c)` pair is consistent with the sender's public key share or any commitment. There is no zero-knowledge proof, no Pedersen commitment, and no consistency check against the public polynomial from DKG. The coordinator simply adds whatever bytes arrive over the channel.

Contrast this with the DKG protocol, which verifies every received share against a broadcast commitment and a proof of knowledge before accepting it: [3](#0-2) 

No equivalent guard exists in the CKD path.

---

### Impact Explanation

A single malicious participant sends an arbitrary pair `(big_y', big_c')` instead of their honest contribution. The coordinator computes:

```
final_big_C = honest_sum + big_c'   (instead of honest_sum + honest_big_c_i)
```

The resulting `CKDOutput` does not equal `H(pk ‖ app_id) · msk`, so `unmask(app_sk)` returns a value that is not the intended confidential derived key. All honest parties accept this silently corrupted output — there is no post-aggregation integrity check. This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept unusable or inconsistent cryptographic outputs**.

---

### Likelihood Explanation

Any participant in the CKD session is a valid attacker. The protocol sends contributions via `chan.send_private` to the coordinator with no authentication of the *content* (only the sender identity is authenticated by the channel). A malicious participant needs only to deviate from `compute_signature_share` and send `(G, G)` or `(identity, identity)` — a trivial one-line change. No special cryptographic capability is required. [4](#0-3) 

---

### Recommendation

Require each participant to accompany their `(big_y, big_c)` contribution with a zero-knowledge proof of correct formation — specifically a proof that `big_c - big_y · app_pk` lies on the line `x_i · H(pk ‖ app_id)` for the participant's committed public share `x_i · G2`. Alternatively, adopt a verifiable secret sharing approach where the coordinator can check each contribution against the participant's public key share from the DKG output before aggregating.

---

### Proof of Concept

1. Run a 3-of-3 CKD session with participants P1 (honest), P2 (honest), P3 (malicious).
2. P3 overrides `do_ckd_participant` to send `(ElementG1::identity(), ElementG1::identity())` instead of the honest `(norm_big_y, norm_big_c)`.
3. The coordinator at lines 50–55 adds the identity elements, producing:
   ```
   final_big_Y = λ1·y1·G + λ2·y2·G + 0
   final_big_C = λ1·(x1·H+y1·A) + λ2·(x2·H+y2·A) + 0
   ```
4. `unmask(app_sk)` returns `final_big_C - app_sk·final_big_Y`, which equals `(λ1·x1 + λ2·x2)·H` — a value that depends only on two of the three shares and does **not** equal `msk·H`.
5. The coordinator outputs this corrupted key as `Some(ckd_output)` with no error, and all honest parties accept it. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L27-33)
```rust
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
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

**File:** src/dkg.rs (L514-527)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
```
