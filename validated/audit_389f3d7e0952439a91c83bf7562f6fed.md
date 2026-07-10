### Title
Missing Validation of `app_pk` Identity Element Allows Malicious Coordinator to Extract Private Signing Shares — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function in the Confidential Key Derivation protocol does not validate that the caller-supplied `app_pk` is a non-identity group element. When `app_pk` is the identity, the ElGamal masking term `app_pk * y` collapses to the identity, stripping the blinding from each participant's share contribution. A malicious coordinator who supplies `app_pk = identity` to all participants receives unmasked per-participant values from which individual private signing shares can be directly computed.

---

### Finding Description

The `ckd()` entry point performs four input checks before launching the protocol: minimum participant count, duplicate detection, self-membership, and coordinator-membership. [1](#0-0) 

It does **not** check that `app_pk` is a valid non-identity public key.

Inside `compute_signature_share`, each participant computes:

```
big_s  = hash_point * private_share_i          // secret contribution
big_c  = big_s + app_pk * y                    // masked with ephemeral y
norm_big_c = lambda_i * big_c                  // Lagrange-weighted
``` [2](#0-1) 

When `app_pk` is the identity element, `app_pk * y = identity`, so:

```
big_c  = big_s + identity = big_s
norm_big_c = lambda_i * hash_point * private_share_i
```

The coordinator receives each participant's `(norm_big_y, norm_big_c)` individually before summing them: [3](#0-2) 

Because `lambda_i` (Lagrange coefficient) and `hash_point = hash_app_id_with_pk(public_key, app_id)` are both publicly computable, the coordinator can invert:

```
private_share_i = norm_big_c_i · (lambda_i · hash_point)^{-1}
```

recovering every participant's BLS signing share.

---

### Impact Explanation

**Critical — Extraction of private signing shares.**

A malicious coordinator who controls the `app_pk` value passed to participants (e.g., by being the entity that distributes protocol parameters) can recover all individual `SigningShare` values. With a threshold number of shares the full master secret key `msk` is reconstructable, enabling unauthorized creation of any CKD output or threshold BLS signature.

This matches the allowed impact: *"Critical: Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets."*

---

### Likelihood Explanation

In a real deployment the coordinator is the natural party that distributes session parameters including `app_pk`. A malicious coordinator can trivially supply the identity element. No cryptographic break, leaked key, or external dependency failure is required — only the ability to influence the `app_pk` argument seen by honest participants, which is within the documented trust model of a malicious coordinator.

---

### Recommendation

Add an explicit check in `ckd()` that `app_pk` is not the identity element before constructing the protocol:

```rust
if app_pk == PublicKey::identity() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the pattern used throughout the codebase where invalid inputs are rejected at the `assert_*` / entry-point layer before any cryptographic computation begins. [4](#0-3) 

---

### Proof of Concept

1. Coordinator is malicious and distributes `app_pk = ElementG1::identity()` to all participants.
2. Each honest participant calls `ckd(..., app_pk = identity, ...)`.
3. Inside `compute_signature_share`, `big_c = big_s + identity * y = big_s = hash_point * private_share_i`.
4. Each participant sends `(lambda_i * big_y, lambda_i * hash_point * private_share_i)` to the coordinator.
5. Coordinator receives individual `norm_big_c_i` values (before summation in the loop at line 50–55).
6. Coordinator computes `hash_point = hash_app_id_with_pk(public_key, app_id)` (public), `lambda_i` (public), and inverts: `private_share_i = norm_big_c_i * (lambda_i * hash_point)^{-1}`.
7. All `t` signing shares are extracted; `msk` is reconstructed via Lagrange interpolation. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L48-57)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L66-117)
```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        key_pair,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
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
