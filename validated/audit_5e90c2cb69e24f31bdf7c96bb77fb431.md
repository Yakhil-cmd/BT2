### Title
Missing Validation of `app_pk` Identity Element in CKD Protocol Allows Confidential Key Extraction - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `ckd` initialization function in `src/confidential_key_derivation/protocol.rs` does not validate that the `app_pk` (client ElGamal public key) parameter is not the group identity element. If a caller supplies `app_pk = G1::identity()`, the ElGamal masking term vanishes, causing the coordinator's `CKDOutput.big_c` to equal `msk · H(pk ‖ app_id)` — the confidential derived key — in plaintext. Any party that calls `unmask(Scalar::ZERO)` on that output recovers the secret directly.

### Finding Description
The `ckd` public entry point validates participant counts, duplicate participants, and coordinator membership, but performs no check that `app_pk` is a valid (non-identity) group element: [1](#0-0) 

The `app_pk` value flows unchanged into `compute_signature_share`, where each participant computes:

```
big_c = big_s + app_pk * y
``` [2](#0-1) 

When `app_pk = G1::identity()`, the term `app_pk * y` collapses to the identity, so `big_c = big_s = x_i · H(pk ‖ app_id)`. After Lagrange-weighted aggregation by the coordinator:

```
total_big_c = Σ λᵢ · big_cᵢ = msk · H(pk ‖ app_id)
```

The `unmask` function then exposes this directly: [3](#0-2) 

Calling `ckd_output.unmask(Scalar::ZERO)` returns `big_c − big_y · 0 = big_c = msk · H(pk ‖ app_id)`, which is the confidential derived key.

### Impact Explanation
**Critical — Extraction/disclosure of confidential derived secrets.**

The confidential derived key `msk · H(pk ‖ app_id)` is the sole secret output of the CKD protocol. With `app_pk = identity`, it is returned in cleartext inside `CKDOutput.big_c`. No cryptographic material beyond the ability to call `ckd` with a chosen `app_pk` is required.

### Likelihood Explanation
The `ckd` function is a public library API. Any caller — including an unprivileged client application — supplies `app_pk`. There is no type-level or runtime guard preventing `ElementG1::identity()` from being passed. The attack requires a single malformed call and is trivially reproducible.

### Recommendation
Add an identity-element check on `app_pk` inside `ckd` before the protocol is launched:

```rust
if app_pk == ElementG1::identity() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
``` [4](#0-3) 

### Proof of Concept

```rust
// Attacker supplies the identity point as app_pk
let app_pk = ElementG1::identity();

// All participants run ckd normally with this app_pk
let protocol = ckd(&participants, coordinator, me, key_pair, app_id, app_pk, rng).unwrap();
// ... run protocol ...

// Coordinator receives CKDOutput where big_c == msk * H(pk || app_id)
let ckd_output: CKDOutput = /* coordinator output */;

// Unmask with zero scalar — no app_sk needed
let confidential_key = ckd_output.unmask(Scalar::ZERO);
// confidential_key == msk * H(pk || app_id)  ← secret extracted
```

The root cause is the absence of a non-identity check on `app_pk` in `ckd` at `src/confidential_key_derivation/protocol.rs` lines 66–117, directly analogous to the missing zero-address checks in the `USDKG` constructor. [5](#0-4)

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
