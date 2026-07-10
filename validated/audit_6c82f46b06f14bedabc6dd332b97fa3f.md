### Title
Missing Validation of Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator in `do_ckd_coordinator` accepts participant-provided group elements `(norm_big_y, norm_big_c)` without any cryptographic validation, allowing a single malicious participant to corrupt the confidential key derivation output by sending arbitrary or identity group elements.

### Finding Description
In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–57), the coordinator receives each participant's `CKDOutput` and blindly accumulates it:

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
- Received `norm_big_y` or `norm_big_c` are not the group identity element.
- The values are consistent with the participant's known public key share (no ZKP or commitment verification).
- The contribution is correctly formed as `(lambda_i * y_i * G, lambda_i * (x_i * H(pk, app_id) + y_i * app_pk))`. [1](#0-0) 

This is in direct contrast to the OT-based presign protocol, which explicitly validates received shares before accumulating them: [2](#0-1) 

The robust presign protocol similarly checks for identity elements and zero scalars before accepting outputs: [3](#0-2) 

The CKD protocol has no analogous guards. The `compute_signature_share` function correctly computes `(lambda_i * y_i * G, lambda_i * (x_i * H(pk, app_id) + y_i * app_pk))` for an honest participant, but the coordinator has no way to enforce this for remote participants. [4](#0-3) 

### Impact Explanation
A malicious participant sends arbitrary group elements — including the identity — for their `(norm_big_y, norm_big_c)` contribution. The coordinator accumulates these unchecked values and produces a `CKDOutput` whose `big_c` component is shifted by the attacker's chosen offset. The subsequent `unmask` operation (`big_c - app_sk * big_y`) then yields a wrong confidential derived key. Honest parties receive and use this corrupted output without any indication of tampering.

**Impact: High** — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs, matching the allowed scope: *"Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs."*

### Likelihood Explanation
Any participant in the CKD protocol can trigger this with zero cryptographic effort — they simply send wrong `ElementG1` values over the channel. The library explicitly targets decentralized MPC networks where participants are untrusted. No key compromise, side-channel, or external dependency is required. The attack is deterministic and silent: the coordinator produces a result without error, and the corruption is only discovered when the derived key is used.

### Recommendation
1. **Identity-element guard**: After accumulation, check that `norm_big_y` and `norm_big_c` are not the group identity before returning `CKDOutput`.
2. **Per-contribution ZKP**: Require each participant to attach a Schnorr proof-of-knowledge demonstrating that their `norm_big_c` was formed as `lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)` relative to their public key share. This is the direct analog of the consistency checks used in the OT-based presign (`big_e == e * G`, `alpha * G == K + A`).
3. **Commitment-then-reveal**: Have participants commit to `(norm_big_y, norm_big_c)` in a first round and reveal in a second, enabling detection of equivocation.

### Proof of Concept
```
Setup: n participants, coordinator C, malicious participant P_m.

1. All honest participants compute and send correct
   (lambda_i * y_i * G, lambda_i * (x_i * H(pk, app_id) + y_i * app_pk)).

2. P_m instead sends (G1::identity(), G1::identity()).

3. Coordinator accumulates:
     norm_big_y = sum_{i != m} lambda_i * y_i * G   (missing P_m's term)
     norm_big_c = sum_{i != m} lambda_i * (x_i * H + y_i * A)  (missing P_m's term)

4. ckd_output = CKDOutput::new(norm_big_y, norm_big_c) — no error raised.

5. unmask(app_sk) computes norm_big_c - app_sk * norm_big_y
   = (msk - lambda_m * x_m) * H(pk, app_id)   ≠   msk * H(pk, app_id).

6. The derived confidential key is wrong. All downstream uses of this key silently fail.
```

Alternatively, `P_m` can send a non-identity offset `(delta_Y, delta_C)` to steer the derived key to any attacker-chosen wrong value, enabling targeted corruption rather than random corruption.

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

**File:** src/confidential_key_derivation/protocol.rs (L148-182)
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
}
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L114-131)
```rust
    for (_, e_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        if e_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        // Spec 1.4
        e += e_j;
    }

    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L226-248)
```rust
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }

    // Step 3.5
    // polynomial interpolation of w
    let (w_2tp1_identifiers, _) = identifiers
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough identifiers".to_string()))?;
    let (w_2tp1_verifying_shares, _) = signingshares
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough verifying shares".to_string()))?;
    let w = Polynomial::eval_interpolation(w_2tp1_identifiers, w_2tp1_verifying_shares, None)?;

    // Step 3.6
    // check w is non-zero
    if w.0.is_zero().into() {
        return Err(ProtocolError::ZeroScalar);
    }
```
