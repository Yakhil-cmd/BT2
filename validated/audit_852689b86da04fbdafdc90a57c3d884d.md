### Title
CKD Coordinator Accepts Unvalidated Participant Shares, Enabling Silent Output Corruption - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The Confidential Key Derivation (CKD) coordinator collects `(big_y, big_c)` shares from every participant and blindly sums them with no validation of the received group elements. A single malicious participant can inject arbitrary or identity-point values, silently corrupting the final `CKDOutput` that the coordinator returns to the application.

---

### Finding Description

In `do_ckd_coordinator` the coordinator loops over all responses from `recv_from_others` and unconditionally adds each participant's `big_y` and `big_c` into the running totals:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [1](#0-0) 

No check is performed on the received values:

- Neither `big_y` nor `big_c` is tested for the identity element (the additive zero of the group).
- There is no zero-knowledge proof or commitment binding the participant's `big_c` to their known public key share.
- There is no final consistency check on `ckd_output` before it is returned.

The honest computation each participant is supposed to perform is:

```rust
let big_y = ElementG1::generator() * y.0;
let big_s = hash_point * private_share.to_scalar();
let big_c = big_s + app_pk * y.0;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [2](#0-1) 

A malicious participant can deviate from this computation and send any pair of group elements. Because the coordinator has no way to verify correctness without knowing the participant's private randomness `y_i`, it cannot distinguish a valid share from a forged one.

---

### Impact Explanation

The `CKDOutput` `(Y, C)` is consumed by the application as:

```
confidential_key = C − app_sk · Y  =  x · H(pk ‖ app_id)
```

If a malicious participant substitutes their honest `(λ_i · y_i · G, λ_i · (x_i · H + y_i · A))` with an arbitrary pair `(P_fake, Q_fake)`, the coordinator computes:

```
Y'  = Y_honest  − λ_i · y_i · G  + P_fake
C'  = C_honest  − λ_i · (x_i · H + y_i · A)  + Q_fake
```

The application then derives `C' − app_sk · Y'`, which is a wrong, attacker-influenced group element instead of the true `x · H(pk ‖ app_id)`. The coordinator has no mechanism to detect this; it returns `Some(ckd_output)` unconditionally.

This maps to: **High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

- Any participant in the CKD session is a valid attacker; no special privilege is required.
- The `ckd` public API accepts an arbitrary `key_pair` and `rng`; a library caller who controls one participant slot can trivially craft a malicious protocol implementation that sends forged shares.
- The attack requires only one round of communication (the single `send_private` call in `do_ckd_participant`) and leaves no detectable trace in the coordinator's output. [3](#0-2) 

---

### Recommendation

1. **Require a proof of correct computation.** Each participant should attach a Schnorr-style zero-knowledge proof demonstrating that `big_c` was formed as `x_i · H(pk, app_id) + y_i · A` for the same `y_i` used to produce `big_y = y_i · G`. The coordinator verifies each proof before adding the share.

2. **Check for identity elements.** At minimum, reject any received `big_y` or `big_c` that equals the group identity before adding it to the running sum.

3. **Add a final output sanity check.** After summing, verify that `norm_big_y` and `norm_big_c` are not the identity element before constructing `CKDOutput`.

---

### Proof of Concept

1. Honest participants `{P1, P2, P3}` run `ckd(...)` with coordinator `P1`.
2. Malicious participant `P2` overrides `do_ckd_participant` to send `(G1::identity(), G1::identity())` instead of its real share.
3. `P1`'s coordinator loop adds the identity elements without error.
4. The returned `CKDOutput` has `Y = Y_P1 + Y_P3` and `C = C_P1 + C_P3`, missing `P2`'s secret contribution `λ_2 · x_2 · H(pk, app_id)`.
5. The application computes `C − app_sk · Y ≠ x · H(pk ‖ app_id)`, silently deriving a wrong confidential key with no error returned. [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L26-33)
```rust
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}
```

**File:** src/confidential_key_derivation/protocol.rs (L35-58)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
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
}
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
