### Title
Malicious Coordinator Presents Inconsistent Participant Sets to CKD Participants, Corrupting the Derived Key Output — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD protocol's single-round design allows a malicious coordinator to present a different `participants` list to each node. Because Lagrange coefficients are computed locally from the caller-supplied list with no cross-participant consensus, the aggregated `(Y, C)` output does not equal `msk · H(pk, app_id)`. The app receives a cryptographically wrong derived key and has no way to detect the corruption.

---

### Finding Description

In `src/confidential_key_derivation/protocol.rs`, the public entry point `ckd()` accepts a `participants: &[Participant]` slice from the caller and immediately constructs a local `ParticipantList` from it. [1](#0-0) 

Each participant then calls `compute_signature_share`, which derives its Lagrange coefficient exclusively from the locally-supplied list: [2](#0-1) 

The coordinator aggregates every received share by simple addition, with no check that each sender used the same `participants` list: [3](#0-2) 

Because the protocol is a single round with no broadcast of the participant set, a malicious coordinator can supply:

- `participants = {A, B, C}` to node A → `λ_A` computed over `{A,B,C}`
- `participants = {A, B, D}` to node B → `λ_B` computed over `{A,B,D}`

The aggregated `C = Σ λ_i · C_i` no longer reconstructs `msk · H(pk, app_id)`, because the Lagrange coefficients do not form a valid reconstruction of the secret over any consistent set.

This is structurally identical to the external report's root cause: a parameter that determines how individual contributions are weighted (the payout calculator / the Lagrange coefficients) is effectively different for each participant, and the aggregator accepts the result without detecting the inconsistency.

---

### Impact Explanation

The app receives a `CKDOutput` `(Y, C)` such that `C − a·Y ≠ msk · H(pk, app_id)`. The derived key `s = HKDF(C − a·Y)` is wrong. The app has no independent way to verify correctness without the master secret key. Honest participants each believe they executed the protocol correctly; none of them can detect the corruption from their local view.

This matches the allowed High impact: **Corruption of CKD outputs so honest parties accept inconsistent participant sets or unusable cryptographic outputs.** [4](#0-3) 

---

### Likelihood Explanation

The coordinator role is assigned by the application layer. Any participant designated as coordinator can trivially supply different `participants` slices to different nodes when invoking `ckd()` on their behalf, since each node's `ckd()` call is independent. No cryptographic material needs to be leaked; the attack requires only the ability to control which `participants` argument each node receives, which is exactly the coordinator's job in the protocol. [5](#0-4) 

---

### Recommendation

Before computing shares, all participants must agree on a canonical `participants` list. The standard fix is to include the sorted, serialized `participants` list in a broadcast or commitment round so that every node can verify it matches what others used. Alternatively, the `participants` list should be bound into the hash input of `hash_app_id_with_pk` (or a session transcript), so that a share computed under a different list is cryptographically incompatible with shares computed under the correct list. [6](#0-5) 

---

### Proof of Concept

**Setup:** 3 participants `{A=1, B=2, C=3}`, threshold 2, coordinator = A.

**Attack:** The malicious coordinator A calls `ckd()` for each node with a different list:
- Node A: `participants = [1, 2, 3]` → `λ_A = lagrange([1,2,3], 1)`
- Node B: `participants = [1, 2, 4]` → `λ_B = lagrange([1,2,4], 2)` (4 is a phantom)
- Node C: `participants = [1, 3, 4]` → `λ_C = lagrange([1,3,4], 3)` (4 is a phantom)

Each node computes `norm_big_c_i = λ_i · (x_i · H(pk, app_id) + y_i · A)` and sends it to A.

A aggregates: `C = norm_big_c_A + norm_big_c_B + norm_big_c_C`.

Because `λ_A + λ_B·(x_B/x_B) + ...` does not equal the Lagrange reconstruction of `msk` over `{1,2,3}`, the result `C − a·Y ≠ msk · H(pk, app_id)`.

The app receives a corrupted `CKDOutput` and derives a wrong key `s`, silently accepting it as correct. [7](#0-6)

### Citations

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

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
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
```

**File:** src/confidential_key_derivation/protocol.rs (L119-146)
```rust
/// Depending on whether the current participant is a coordinator or not,
/// runs the ckd protocol as either a participant or a coordinator.
#[allow(clippy::too_many_arguments)]
async fn run_ckd_protocol(
    chan: SharedChannel,
    coordinator: Participant,
    me: Participant,
    participants: ParticipantList,
    key_pair: KeygenOutput,
    app_id: AppId,
    app_pk: PublicKey,
    mut rng: impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    if me == coordinator {
        do_ckd_coordinator(chan, participants, me, &key_pair, &app_id, app_pk, &mut rng).await
    } else {
        do_ckd_participant(
            chan,
            &participants,
            coordinator,
            me,
            &key_pair,
            &app_id,
            app_pk,
            &mut rng,
        )
    }
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

**File:** src/confidential_key_derivation/mod.rs (L65-71)
```rust
/// Hashes the app id and the public key as of
/// H(pk || `app_id`) where H is a random oracle
pub fn hash_app_id_with_pk(pk: &VerifyingKey, app_id: &[u8]) -> ElementG1 {
    let compressed_pk = pk.to_element().to_compressed();
    let input = [compressed_pk.as_slice(), app_id].concat();
    ciphersuite::hash_to_curve(&input)
}
```
