### Title
Unvalidated `app_pk` Parameter Allows Malicious Coordinator to Bypass ElGamal Masking and Extract Confidential Derived Key — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` entry point accepts an `app_pk` (`PublicKey = ElementG1`) parameter with no check that it is a non-identity curve point. The CKD protocol's confidentiality guarantee rests entirely on ElGamal masking: each participant computes `C_i = S_i + y_i · app_pk`. When `app_pk` is the G1 identity element, scalar multiplication yields the identity, the masking term vanishes, and the coordinator directly aggregates the unmasked secret `S = msk · H(pk, app_id)`.

---

### Finding Description

The CKD protocol is designed so that the coordinator learns only the ElGamal ciphertext `(Y, C)` and cannot recover `S = msk · H(pk, app_id)` without the application's secret scalar `app_sk`. The masking is computed inside `compute_signature_share`:

```
big_c = big_s + app_pk * y   // ElGamal encryption of big_s under app_pk
``` [1](#0-0) 

If `app_pk = G1::identity()`, then `app_pk * y = identity` for any scalar `y`, so `big_c = big_s`. Every participant's normalized contribution becomes `norm_big_c_i = λ_i · S_i`. The coordinator's aggregation loop:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();   // accumulates λ_i · S_i
}
``` [2](#0-1) 

produces `C = Σ λ_i · S_i = msk · H(pk, app_id)` — the confidential derived key — in the clear.

The public `ckd()` initializer validates participant-list membership and duplicate detection but performs **no check** on `app_pk`: [3](#0-2) 

The type `PublicKey = ElementG1 = blstrs::G1Projective` can represent the identity element at the Rust type level; the identity-rejection guard present in the `BLS12381G1Group::deserialize` path is never reached when `app_pk` is passed directly as an already-constructed `ElementG1`. [4](#0-3) 

---

### Impact Explanation

**Critical — Extraction of confidential derived secrets.**

The entire confidentiality property of the CKD protocol is that the coordinator cannot learn `S`. With `app_pk = G1::identity()`, the coordinator aggregates `C = S` directly and reads the confidential derived key without possessing `app_sk`. This is the exact secret the protocol is designed to protect, as stated in the module documentation: [5](#0-4) 

---

### Likelihood Explanation

In any realistic deployment the coordinator is the entity that distributes `app_pk` to participants (the protocol itself has no in-band mechanism for participants to agree on `app_pk`). A malicious coordinator therefore controls the value every participant passes to `ckd()`. No cryptographic capability is required — passing the identity element is a trivial operation. The protocol provides no defense because `ckd()` never rejects it.

---

### Recommendation

Add an explicit identity-point check at the top of `ckd()`, mirroring the guard already present in deserialization:

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
+   if bool::from(app_pk.is_identity()) {
+       return Err(InitializationError::BadParameters(
+           "app_pk must not be the identity element".to_string(),
+       ));
+   }
    // ... existing participant checks ...
}
```

Additionally, consider broadcasting `app_pk` among participants via the echo-broadcast channel so that all honest parties can verify they are operating on the same value, preventing a malicious coordinator from supplying different `app_pk` values to different participants.

---

### Proof of Concept

1. Malicious coordinator sets `app_pk = blstrs::G1Projective::identity()`.
2. Coordinator distributes this value out-of-band to all participants (the protocol has no in-band `app_pk` agreement).
3. Each participant calls `ckd(..., app_pk = identity, ...)`. The call succeeds — no error is returned.
4. Inside `compute_signature_share`, each participant computes:
   - `big_c_i = big_s_i + identity * y_i = big_s_i`
   - `norm_big_c_i = λ_i · big_s_i`
5. Coordinator's aggregation loop accumulates `C = Σ λ_i · S_i = msk · H(pk, app_id)`.
6. Coordinator reads `S` directly from `ckd_output.big_c()` — no `app_sk` required. [6](#0-5) [7](#0-6)

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

**File:** src/confidential_key_derivation/ciphersuite.rs (L194-213)
```rust
    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }

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

**File:** src/confidential_key_derivation/mod.rs (L1-10)
```rust
//! Confidential Key Derivation (CKD) protocol.
//!
//! This module provides the implementation of the Confidential Key Derivation (CKD) protocol,
//! which allows a client to derive a unique key for a specific application without revealing
//! the application identifier to the key derivation service.
//!
//! The protocol is based on a combination of Oblivious Transfer (OT) and Diffie-Hellman key exchange.
//!
//! For more details, refer to the `confidential-key-derivation.md` document in the `docs` folder.

```
