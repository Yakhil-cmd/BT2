### Title
Missing Participant-to-Key-Material Binding in `ckd()` Allows CKD Output Corruption — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function accepts a `me: Participant` identity and a `key_pair: KeygenOutput` without verifying that the private share inside `key_pair` actually belongs to `me`. A caller can pass `me = participant_A` with `key_pair` containing participant B's private share. The protocol runs to completion without error, but the coordinator aggregates a cryptographically invalid share, producing a `CKDOutput` that does not decrypt to the correct confidential derived key. Honest parties accept this corrupted output.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the `ckd()` entry-point validates that `me` is present in the participant list: [1](#0-0) 

However, it never validates that `key_pair.private_share` is the share corresponding to `me`. The `compute_signature_share()` function independently uses the private share from `key_pair` and the Lagrange coefficient derived from `me`: [2](#0-1) 

Specifically, line 157 extracts `key_pair.private_share` (which may belong to participant B), while line 177 computes `lambda_i` for `me` (participant A). The resulting normalized share `norm_big_c = (hash_point * share_B + app_pk * y) * lambda_A` is cryptographically incorrect. The coordinator at lines 50–55 sums all received shares without any per-participant verification: [3](#0-2) 

The same structural issue exists in `src/ecdsa/ot_based_ecdsa/presign.rs`. The `presign()` function accepts `me: Participant` and `args: PresignArguments` (which contains `keygen_out: KeygenOutput`) without verifying that `keygen_out.private_share` belongs to `me`. The code even contains an explicit comment acknowledging that ownership of the provided material is not checked: [4](#0-3) 

Inside `do_presign`, `args.keygen_out.private_share.to_scalar()` is multiplied by `lambda_me` (the Lagrange coefficient for `me`), producing a corrupted `sigma_i` if the share belongs to a different participant: [5](#0-4) 

---

### Impact Explanation

A caller invoking `ckd(participants, coordinator, participant_A, key_pair_B, app_id, app_pk, rng)` causes the CKD protocol to complete without any error. The coordinator aggregates a share computed with the wrong private key scaled by the wrong Lagrange coefficient. The resulting `CKDOutput` does not decrypt to the correct confidential derived key — `ckd_output.unmask(app_sk)` yields a value different from `hash_app_id_with_pk(&pk, &app_id) * msk`. Honest parties (coordinator and downstream consumers) accept this corrupted output as valid.

This maps to the allowed **High** impact: *Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.*

For the presign analog, the corrupted `sigma_i` propagates into the `PresignOutput`, causing all subsequent signing attempts using that presignature to produce invalid ECDSA signatures, permanently denying signing for honest parties under valid protocol inputs.

---

### Likelihood Explanation

`ckd()` and `presign()` are public library APIs. Any application-layer caller — including a misconfigured MPC node or a malicious participant controlling its own process — can trivially supply a mismatched `me` and `key_pair`. The `KeygenOutput` struct contains only `private_share` and the aggregate `public_key` (which is identical for all participants), so there is no caller-visible signal that the pairing is wrong. No runtime check, assertion, or documentation warning prevents this mismatch.

---

### Recommendation

Include the participant's individual verification share (`VerifyingKey` share) in `KeygenOutput`. Before executing the protocol, verify that `private_share * G == individual_verification_share` and that `individual_verification_share` is the commitment evaluation at `me`'s identifier. This binds the private share to the claimed participant identity before any protocol computation begins, analogous to the recommended `require(exeOrder.account == _params._account)` in the external report.

---

### Proof of Concept

```rust
// Assume DKG has been run for participants [A, B, C]
// key_packages[0] = (participant_A, KeygenOutput { private_share: share_A, public_key: pk })
// key_packages[1] = (participant_B, KeygenOutput { private_share: share_B, public_key: pk })

// Malicious / misconfigured call: me = participant_A, but key_pair = participant_B's output
let protocol = ckd(
    &participants,
    coordinator,
    participant_A,          // <-- claimed identity: A
    key_packages[1].1,      // <-- key material: belongs to B
    app_id.clone(),
    app_pk,
    rng,
).unwrap();

// Protocol completes without error.
// Coordinator aggregates: share_B * lambda_A + share_A * lambda_A + share_C * lambda_C
// This is NOT equal to share_A * lambda_A + share_B * lambda_B + share_C * lambda_C (correct)
// ckd_output.unmask(app_sk) != hash_app_id_with_pk(&pk, &app_id) * msk
// CKD output is silently corrupted.
```

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

**File:** src/confidential_key_derivation/protocol.rs (L87-93)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L155-181)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-41)
```rust
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L101-103)
```rust
    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;
```
