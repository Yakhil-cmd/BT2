### Title
Malicious Participant Can Corrupt CKD Output by Supplying Mismatched `public_key` in `KeygenOutput` - (File: src/confidential_key_derivation/protocol.rs)

---

### Summary

The `ckd` function in `src/confidential_key_derivation/protocol.rs` accepts a caller-supplied `KeygenOutput` struct containing both a `private_share` and a `public_key`. The `compute_signature_share` helper uses `key_pair.public_key` as a domain-separator input to `hash_app_id_with_pk`, which determines the hash-to-curve point that each participant's private share is multiplied against. The protocol never verifies that `key_pair.public_key` equals the actual group public key agreed upon during key generation. A malicious participant can supply a `KeygenOutput` whose `public_key` field is an arbitrary G2 point while keeping their real `private_share`, causing their contribution to the aggregated CKD output to be computed over a different hash point. The coordinator aggregates all contributions without any per-participant consistency check, so honest parties accept a silently corrupted CKD output.

---

### Finding Description

In `compute_signature_share` (called by both `do_ckd_participant` and `do_ckd_coordinator`):

```rust
// src/confidential_key_derivation/protocol.rs  lines 148-181
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    let private_share = Zeroizing::new(key_pair.private_share);
    let y = Scalar::random(rng);
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));
    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) — uses key_pair.public_key, never validated
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    let big_s = hash_point * private_share.to_scalar();
    let big_c = big_s + app_pk * y.0;

    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
}
```

The coordinator then aggregates without any per-participant verification:

```rust
// lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The expected CKD output is `msk · H(pk, app_id)` where `pk` is the group public key and `msk` is the master secret key. If participant `i` supplies `pk′ ≠ pk`, their contribution becomes:

```
λᵢ · xᵢ · H(pk′, app_id)   instead of   λᵢ · xᵢ · H(pk, app_id)
```

The aggregated `norm_big_c` becomes:

```
msk · H(pk, app_id)  +  λᵢ · xᵢ · (H(pk′, app_id) − H(pk, app_id))
```

which is not equal to the expected value. The `unmask(app_sk)` call on this output recovers an incorrect confidential key. No error is raised; honest parties silently accept the corrupted result.

The analog to the original report is direct: just as `NftAttempts` was accepted without verifying its `mint_pubkey` matched the `Stake` account's mint, here `key_pair.public_key` is accepted without verifying it matches the actual group public key that all other participants are using.

---

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept unusable cryptographic outputs.**

The coordinator and all honest participants receive and store a `CKDOutput` whose `norm_big_c` component is silently wrong. Any downstream consumer that calls `ckd_output.unmask(app_sk)` recovers a key that does not equal `msk · H(pk, app_id)`. The application-level secret derived from this CKD run is permanently incorrect for this invocation, and honest parties have no in-protocol signal that anything went wrong.

---

### Likelihood Explanation

**Medium.** Any participant who is legitimately enrolled in the CKD protocol can trivially mount this attack by constructing a `KeygenOutput` with an arbitrary `public_key` (any valid G2 point) while retaining their real `private_share`. No cryptographic capability beyond normal participation is required. The attack is a single-field substitution in a locally constructed struct before calling `ckd(...)`.

---

### Recommendation

Pass the expected group public key as an explicit, trusted parameter to `ckd` (separate from the caller-supplied `KeygenOutput`) and assert equality before entering the protocol:

```rust
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    expected_public_key: &VerifyingKey,   // <-- add this
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    if key_pair.public_key != *expected_public_key {
        return Err(InitializationError::BadParameters(
            "key_pair.public_key does not match the expected group public key".to_string(),
        ));
    }
    // ... rest of function
}
```

This mirrors the fix in the original report: verify that the account/state field (`key_pair.public_key`) matches the authoritative reference (`expected_public_key`) before using it in any computation.

---

### Proof of Concept

1. Run a legitimate DKG to obtain `(pk, [xᵢ])` for `n` participants.
2. Participant `i` (malicious) constructs:
   ```rust
   let fake_pk = VerifyingKey::new(G2Projective::generator() * Scalar::random(&mut rng));
   let malicious_key_pair = KeygenOutput {
       public_key: fake_pk,      // wrong group public key
       private_share: real_xᵢ,  // real private share
   };
   ```
3. Participant `i` calls `ckd(participants, coordinator, me, malicious_key_pair, app_id, app_pk, rng)`.
4. The coordinator aggregates all contributions. Participant `i`'s `big_s = H(fake_pk, app_id) · xᵢ` instead of `H(pk, app_id) · xᵢ`.
5. The coordinator outputs `CKDOutput` with corrupted `norm_big_c`.
6. Any caller of `ckd_output.unmask(app_sk)` recovers a key ≠ `msk · H(pk, app_id)`.
7. No error is returned at any step; honest parties silently accept the wrong output. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/confidential_key_derivation/protocol.rs (L66-116)
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
