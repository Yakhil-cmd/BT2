### Title
Missing Validation of Participant Contributions in CKD Accumulation Loop Allows Output Corruption - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `do_ckd_coordinator` function in the Confidential Key Derivation (CKD) protocol accumulates `big_y` and `big_c` group elements from each participant in a loop without validating that the received values are non-identity (non-zero) group elements or that they are correctly formed. A malicious participant can send identity elements or arbitrary crafted group elements, silently corrupting the aggregated CKD output. The coordinator accepts and propagates the corrupted result to the requester, who then unmasks an incorrect confidential derived key.

### Finding Description

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 50–55), the coordinator receives each participant's `CKDOutput` and unconditionally adds `big_y` and `big_c` into the running totals:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

There is no check that:
- `participant_output.big_y()` is not the identity element (the group-theoretic equivalent of `0x00`)
- `participant_output.big_c()` is not the identity element
- The received values are consistent with the participant's committed key share

Compare this to the DKG share accumulation loop in `src/dkg.rs` (lines 514–527), which explicitly calls `validate_received_share` against the participant's committed polynomial before accumulating:

```rust
validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;
my_signing_share = my_signing_share + signing_share_from.to_scalar();
```

The CKD accumulation loop has no analogous validation step. The `compute_signature_share` function in `src/confidential_key_derivation/protocol.rs` (lines 148–181) correctly computes `(λ_i · y_i · G, λ_i · (x_i · H(pk, app_id) + y_i · app_pk))`, but a malicious participant is not bound to use this computation — they can send any `CKDOutput` they choose.

### Impact Explanation

The CKD output `(Y, C)` is constructed as:
- `Y = Σ λ_i · y_i · G`
- `C = Σ λ_i · (x_i · H(pk, app_id) + y_i · app_pk)`

The requester unmasks with `C − app_sk · Y = msk · H(pk, app_id)` (the confidential derived key).

A malicious participant who sends `big_y = identity` and `big_c = identity` effectively removes their contribution from the sum. The resulting `(Y', C')` is missing that participant's share, so the unmasked value is not `msk · H(pk, app_id)` — it is a different, incorrect group element. Honest parties (coordinator and requester) accept this corrupted output without any indication of failure.

A more targeted attack: the malicious participant sends `big_y = identity` and `big_c = arbitrary_crafted_point`. This injects an attacker-controlled additive offset into `C` while leaving `Y` unaffected, producing a deterministically biased output that the attacker controls but honest parties cannot distinguish from a legitimate result.

**Impact class:** High — Corruption of CKD outputs so honest parties accept unusable or attacker-biased cryptographic outputs.

### Likelihood Explanation

Any single malicious participant in the CKD session can trigger this. No special capabilities, leaked keys, or cryptographic breaks are required. The attacker simply sends a crafted `CKDOutput` message to the coordinator instead of the honest computation. The coordinator has no mechanism to detect the deviation. Likelihood is high.

### Recommendation

Add per-participant validation before accumulating contributions in `do_ckd_coordinator`. At minimum:

1. **Reject identity elements**: Check that `participant_output.big_y()` and `participant_output.big_c()` are not the identity element of G1 before adding them.
2. **Add a zero-knowledge proof of correct share formation**: Each participant should accompany their `(big_y, big_c)` with a proof that `big_c = x_i · H(pk, app_id) + y_i · app_pk` and `big_y = y_i · G` for the same `y_i`, without revealing `y_i` or `x_i`. This is analogous to the DKG proof-of-knowledge step.
3. **Post-accumulation identity check**: After the loop, verify that `norm_big_y` and `norm_big_c` are not the identity before constructing `CKDOutput`.

### Proof of Concept

1. Honest participants `P_1, …, P_{n-1}` and malicious participant `P_n` run the CKD protocol.
2. `P_n` is a participant (not the coordinator). When it is time to send its `CKDOutput` to the coordinator, `P_n` sends `CKDOutput { big_y: G1::identity(), big_c: G1::identity() }` instead of the honest computation.
3. The coordinator's loop at `src/confidential_key_derivation/protocol.rs:50–55` adds `identity` to both `norm_big_y` and `norm_big_c` — a no-op — silently dropping `P_n`'s legitimate contribution.
4. `CKDOutput::new(norm_big_y, norm_big_c)` is returned to the requester.
5. The requester calls `ckd_output.unmask(app_sk)` and obtains `C_honest − app_sk · Y_honest`, which is not equal to `msk · H(pk, app_id)` because `P_n`'s share of `msk` is missing from the sum.
6. The requester silently accepts an incorrect confidential derived key with no error or warning. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
```rust
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    // Ensures the value is zeroized on drop
    let private_share = Zeroizing::new(key_pair.private_share);

    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

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

**File:** src/dkg.rs (L514-528)
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
    }
```
