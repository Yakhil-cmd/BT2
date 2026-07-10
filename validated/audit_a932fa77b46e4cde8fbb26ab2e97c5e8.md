### Title
Missing Proof of Correctness for Participant Contributions in CKD Protocol Allows Malicious Participant to Corrupt CKD Output - (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator in `do_ckd_coordinator` blindly sums participant-supplied `(big_y, big_c)` group elements without any proof of correctness. A single malicious participant can send arbitrary curve points, causing the coordinator to produce a corrupted `CKDOutput` that yields a wrong confidential key when unmasked by the TEE application.

---

### Finding Description

The CKD protocol is a one-round protocol where each participant sends their share `(norm_big_y, norm_big_c)` to the coordinator, and the coordinator sums all contributions to produce the final output.

In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–57):

```rust
async fn do_ckd_coordinator(...) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();   // no verification
        norm_big_c += participant_output.big_c();   // no verification
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}
``` [1](#0-0) 

Each honest participant is supposed to compute:

- `norm_big_y = lambda_i * y_i * G`
- `norm_big_c = lambda_i * (x_i * H(pk || app_id) + y_i * A)`

as implemented in `compute_signature_share` (`src/confidential_key_derivation/protocol.rs`, lines 148–181): [2](#0-1) 

The coordinator then sums all contributions so that:

- `Y = Σ lambda_i * y_i * G`
- `C = msk * H(pk || app_id) + Y * a`

and the TEE application unmasks via `C - a * Y = msk * H(pk || app_id)` as defined in `CKDOutput::unmask` (`src/confidential_key_derivation/mod.rs`, lines 54–56): [3](#0-2) 

**There is no zero-knowledge proof, commitment scheme, or any other mechanism to verify that a participant's `(big_y, big_c)` was computed correctly.** A malicious participant can send any arbitrary `(big_y', big_c')` pair. The coordinator has no way to detect this.

If a malicious participant sends `(big_y', big_c')` instead of the correct values, the coordinator computes:

```
Y'  = Y_correct + (big_y' - lambda_i * y_i * G)
C'  = C_correct + (big_c' - lambda_i * (x_i * H(pk||app_id) + y_i * A))
```

When the TEE application calls `unmask(app_sk)`:

```
C' - a * Y' = msk * H(pk||app_id) + Δ
```

where `Δ` is an attacker-controlled nonzero offset, yielding a completely wrong confidential key.

**Contrast with ECDSA protocols**: Both the OT-based and Robust ECDSA presign protocols include explicit consistency checks on received participant contributions. For example, in `src/ecdsa/ot_based_ecdsa/presign.rs`:

```rust
// E =?= e*G
if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
    return Err(ProtocolError::AssertionFailed(...));
}
// alpha*G =?= K + A, beta*G =?= X + B
if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
    || (ProjectivePoint::GENERATOR * beta != big_x + big_b) { ... }
``` [4](#0-3) 

The Robust ECDSA presign also performs exponent interpolation checks on received shares: [5](#0-4) 

The CKD protocol has no equivalent protection.

---

### Impact Explanation

**High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

A malicious participant corrupts the coordinator's `CKDOutput`. The TEE application derives a wrong confidential key `msk * H(pk || app_id) + Δ` instead of the correct one. The application silently accepts this wrong key, leading to complete failure of the confidential key derivation for the targeted `app_id`. The honest coordinator and other participants have no way to detect the corruption.

---

### Likelihood Explanation

Any single participant in the CKD protocol can execute this attack. The protocol has only one round of communication and no mechanism to detect or attribute incorrect contributions. The attacker needs only to be a registered participant with a valid key share — no additional privileges are required. The attack is trivially executable by modifying the `do_ckd_participant` path to send arbitrary group elements. [6](#0-5) 

---

### Recommendation

Add a non-interactive zero-knowledge proof (e.g., a Sigma protocol / Chaum-Pedersen proof) that each participant's `(big_y, big_c)` was computed correctly with respect to their committed public key share. Specifically, each participant should prove knowledge of `y_i` and `x_i` such that:

- `big_y = lambda_i * y_i * G`
- `big_c = lambda_i * x_i * H(pk || app_id) + lambda_i * y_i * A`

This is consistent with the approach used in the ECDSA presign protocols, which verify participant contributions against public commitments before accepting them.

---

### Proof of Concept

1. Honest participants `P1, P2, P3` run `ckd()` with `P1` as coordinator.
2. Malicious `P2` overrides `do_ckd_participant` to send `(G, G)` (the generator point) instead of the correctly computed `(norm_big_y, norm_big_c)`.
3. `P1`'s coordinator loop at lines 50–55 adds `P2`'s arbitrary `(G, G)` into the running sum without any check.
4. The resulting `CKDOutput` has `big_y` and `big_c` shifted by `G` relative to the correct values.
5. The TEE application calls `ckd_output.unmask(app_sk)` and receives `msk * H(pk || app_id) + G - app_sk * G`, which is wrong.
6. The application silently uses the wrong confidential key with no error or warning. [7](#0-6)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L17-33)
```rust
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
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

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L126-168)
```rust
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }

    // Round 2
    // alphai = ki' + ai'
    // Spec 2.1
    let alpha_i: Scalar = k_prime_i + a_prime_i;
    // betai = xi' + bi'
    let beta_i: Scalar = x_prime_i + b_prime_i;

    // Send alphai and betai
    // Spec 2.2
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &(alpha_i, beta_i))?;

    // Receive and compute alpha = SUM_j alphaj
    // Receive and compute beta = SUM_j betaj
    // Spec 2.3
    let mut alpha = alpha_i;
    let mut beta = beta_i;

    for (_, (alpha_j, beta_j)) in
        recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
    {
        // Spec 2.4
        alpha += alpha_j;
        beta += beta_j;
    }

    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L193-213)
```rust
    // check that the exponent interpolations match what has been received
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }
```
