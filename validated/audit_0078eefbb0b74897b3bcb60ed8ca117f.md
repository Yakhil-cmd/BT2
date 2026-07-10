### Title
Missing Identity-Element Check on `app_pk` in CKD Protocol Allows Coordinator to Learn Confidential Derived Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `ckd()` entry point and the internal `compute_signature_share()` function accept a caller-supplied `app_pk: PublicKey` (a `blstrs::G1Projective` element) without verifying it is not the group identity. When `app_pk` is the identity element, the ElGamal masking term `y * A` collapses to the identity, and the coordinator receives the unmasked confidential derived key `msk * H(app_id)` directly in `big_c`.

### Finding Description
The CKD protocol is designed as a threshold ElGamal encryption of `msk * H(app_id)` under the TEE app's ephemeral public key `A`. Each participant computes:

```
C_i = x_i * H(app_id) + y_i * A
```

and sends `(λ_i * Y_i, λ_i * C_i)` to the coordinator, who sums them to obtain `(Y, C)` where `C = msk * H(app_id) + y * A`. The masking term `y * A` is what prevents the coordinator from learning the derived key.

In `compute_signature_share` there is no check that `app_pk` is not the identity:

```rust
// src/confidential_key_derivation/protocol.rs  ~line 174
let big_c = big_s + app_pk * y.0;   // app_pk is never validated
```

If `app_pk = G1::identity()`, then `app_pk * y.0 = identity`, so `big_c = big_s = x_i * H(app_id)`. After Lagrange interpolation the coordinator holds `big_c = msk * H(app_id)` in the clear.

The public entry point `ckd()` validates participant lists and threshold parameters but performs no check on `app_pk`:

```rust
// src/confidential_key_derivation/protocol.rs  lines 66-116
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    key_pair: KeygenOutput,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,          // ← no identity check anywhere
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    ...
    // participant/coordinator membership checks only
    ...
}
``` [1](#0-0) [2](#0-1) 

### Impact Explanation
When `app_pk = G1::identity()` the coordinator's output field `big_c` equals `msk * H(app_id)` — the confidential derived secret — without any masking. The coordinator, which is a participant in the MPC network, directly observes the derived key that the protocol is designed to keep hidden from all MPC nodes. This constitutes **disclosure of a confidential derived secret** to a party that should never learn it.

Impact classification: **Critical** — matches "Extraction, reconstruction, or disclosure of … confidential derived secrets."

### Likelihood Explanation
The `app_pk` is a caller-supplied `blstrs::G1Projective` value. The Rust type admits the identity element with no special encoding; a caller passes `G1Projective::identity()` (or its serialized all-zero compressed form). No out-of-band mechanism prevents this. Any entity that can invoke `ckd()` — including a malicious or compromised TEE app — can trigger the condition with a single-line change.

### Recommendation
Add an explicit identity-element check on `app_pk` at the `ckd()` entry point before the protocol is started:

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

Analogously, `compute_signature_share` should assert the same invariant defensively. This mirrors the pattern already used elsewhere in the codebase (e.g., `BLS12381G1Group::deserialize` rejects the identity, and `robust_ecdsa/presign.rs` checks `big_r != identity` before proceeding). [3](#0-2) [4](#0-3) 

### Proof of Concept

1. Caller invokes `ckd()` with `app_pk = blstrs::G1Projective::identity()`.
2. Inside `compute_signature_share`, each participant computes:
   - `big_y = G1::generator() * y`  (random, non-zero)
   - `big_s = H(pk || app_id) * x_i`
   - `big_c = big_s + identity * y = big_s`  ← masking term vanishes
3. Coordinator aggregates: `sum(λ_i * big_c_i) = msk * H(pk || app_id)`.
4. The coordinator's `CKDOutput::big_c` field now holds the confidential derived key in the clear.
5. Any observer of the coordinator output (including the coordinator itself) can read `msk * H(app_id)` directly without knowing `app_sk`, by calling `ckd_output.unmask(Scalar::ZERO)`. [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/ecdsa/robust_ecdsa/presign.rs (L225-232)
```rust
    // check R is not identity
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }
```

**File:** src/confidential_key_derivation/mod.rs (L52-56)
```rust
    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
