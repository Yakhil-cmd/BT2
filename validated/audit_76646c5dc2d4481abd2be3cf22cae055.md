### Title
Missing Identity-Element Check for `app_pk` in `ckd()` Allows Coordinator to Directly Recover Confidential Derived Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `ckd()` initialization function in `src/confidential_key_derivation/protocol.rs` accepts `app_pk: PublicKey` (a `blstrs::G1Projective` element) without validating that it is not the group identity element. If `app_pk` is the identity, the ElGamal masking term `app_pk * y` collapses to the identity, causing the aggregated `CKDOutput.big_c` to directly equal the confidential derived key `msk · H(pk ∥ app_id)` — readable by the coordinator without the TEE's secret key.

### Finding Description
The CKD protocol is designed so that each participant computes a masked share:

```
C_i = S_i + app_pk · y_i
Y_i = y_i · G
```

where `S_i = x_i · H(pk ∥ app_id)` is the secret share contribution and `y_i` is a per-participant blinding scalar. The coordinator aggregates these into `(Y, C)` and the TEE recovers the derived key via `unmask(app_sk) = C − app_sk · Y`.

The masking relies entirely on `app_pk` being a non-identity point. In `compute_signature_share()`:

```rust
// C <- S + y . A
let big_c = big_s + app_pk * y.0;
``` [1](#0-0) 

If `app_pk = G1::identity()`, then `app_pk * y.0 = identity`, so `big_c = big_s = x_i · H(pk ∥ app_id)`. After Lagrange-weighted aggregation by the coordinator:

```
C = Σ λ_i · big_c_i = msk · H(pk ∥ app_id)
```

The `CKDOutput` returned to the coordinator directly contains the confidential derived key in `big_c`, with no masking. The coordinator does not need `app_sk` to read it.

The `ckd()` function performs several input checks (participant count, duplicates, self-membership, coordinator membership) but performs **no check** that `app_pk` is a non-identity element: [2](#0-1) 

`PublicKey` is a raw `blstrs::G1Projective` type alias with no type-level non-identity invariant: [3](#0-2) 

By contrast, the `BLS12381G1Group::deserialize` implementation does reject the identity element — but only when deserializing from bytes, not when a `G1Projective` value is passed directly to `ckd()`: [4](#0-3) 

### Impact Explanation
A malicious coordinator who controls the `app_pk` value distributed to participants (the coordinator is the natural relay between the TEE and the signing participants) can pass `app_pk = G1Projective::identity()` to all participants. The resulting `CKDOutput.big_c` equals `msk · H(pk ∥ app_id)` — the confidential derived key — directly, without requiring the TEE's secret key `app_sk`. This constitutes **disclosure of a confidential derived secret**, matching the Critical impact tier.

### Likelihood Explanation
The coordinator is the natural distributor of the CKD request parameters (including `app_pk`) to all participants. A malicious coordinator can substitute the identity element for the real TEE public key. No cryptographic primitive break is required; the attack is a single parameter substitution. The library provides no defense: `ckd()` accepts any `G1Projective` value without validation.

### Recommendation
Add an identity-element check for `app_pk` in `ckd()` before the protocol is launched, analogous to the existing participant-membership checks:

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk cannot be the identity element".to_string(),
    ));
}
``` [5](#0-4) 

### Proof of Concept
1. Caller invokes `ckd(participants, coordinator, me, key_pair, app_id, G1Projective::identity(), rng)`.
2. `ckd()` passes all existing checks (participant count, duplicates, membership).
3. Each participant's `compute_signature_share` computes `big_c = big_s + identity * y = big_s`.
4. The coordinator aggregates: `C = Σ λ_i · x_i · H(pk ∥ app_id) = msk · H(pk ∥ app_id)`.
5. The coordinator reads `ckd_output.big_c()` and obtains the confidential derived key directly, without calling `unmask` or possessing `app_sk`. [6](#0-5)

### Citations

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

**File:** src/confidential_key_derivation/mod.rs (L62-62)
```rust
pub type PublicKey = ElementG1;
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L202-213)
```rust
    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
```
