### Title
Missing Identity-Element Check on `app_pk` in `ckd()` Allows Coordinator to Directly Recover the Confidential Derived Key - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` entry-point function accepts an `app_pk: PublicKey` (`ElementG1 = blstrs::G1Projective`) argument but never validates that it is not the group identity (point at infinity). When `app_pk` equals the identity element, the ElGamal masking term `app_pk * y` collapses to the identity for every participant, causing the coordinator to receive the unmasked confidential derived key `msk · H(pk ‖ app_id)` in the clear — without needing the application's secret scalar `app_sk`.

---

### Finding Description

The CKD protocol is designed as an ElGamal-style masked delivery:

```
big_s  = x_i · H(pk ‖ app_id)          // participant's share of the secret
big_c  = big_s + app_pk · y             // masked with ephemeral y and app_pk
norm_big_y = λ_i · (y · G)
norm_big_c = λ_i · big_c
```

After the coordinator aggregates all shares:

```
total_big_c = msk · H(pk ‖ app_id) + app_pk · Y_total
total_big_y = Y_total · G
```

The application unmasks with `total_big_c − app_sk · total_big_y = msk · H(pk ‖ app_id)`.

The confidentiality guarantee holds **only if** `app_pk ≠ identity`. If `app_pk = identity`:

```
big_c = big_s + identity · y = big_s = x_i · H(pk ‖ app_id)
total_big_c = msk · H(pk ‖ app_id)   // no masking at all
```

The coordinator's output field `big_c` **is** the confidential derived key, readable directly from the `CKDOutput` struct without calling `unmask`.

The `ckd()` function performs several input checks (participant count, duplicates, self-membership, coordinator membership) but contains **no check** that `app_pk` is not the identity element: [1](#0-0) 

The masking computation that silently degenerates when `app_pk = identity` is: [2](#0-1) 

The `CKDOutput` type exposes `big_c` directly via a public getter, so the coordinator can read the unmasked key without any further computation: [3](#0-2) 

---

### Impact Explanation

**Critical — Disclosure of confidential derived secrets.**

When `app_pk = identity`, the coordinator's `CKDOutput::big_c` field equals `msk · H(pk ‖ app_id)` — the exact confidential derived key the protocol is designed to keep secret from the coordinator. Any party that observes the coordinator's output (the coordinator itself, or any observer of the protocol transcript) obtains the secret without possessing `app_sk`. This directly satisfies the allowed Critical impact: *"Extraction, reconstruction, or disclosure of … confidential derived secrets."*

---

### Likelihood Explanation

**Medium.** The `app_pk` value is supplied by the caller of `ckd()` — typically an integration layer that forwards the application's public key received over an API or RPC call. An uninitialized, zeroed, or default-constructed `ElementG1` in Rust (`G1Projective::identity()`) is the identity element. A scripting or integration mistake — exactly the scenario described in the reference report — where `app_pk` is left at its zero/default value would silently bypass all masking. No cryptographic break or privileged access is required; only a missing field in a caller-supplied struct.

---

### Recommendation

Add an explicit identity-element guard at the top of `ckd()`, immediately after the existing participant-list checks:

```rust
// Reject the identity element: app_pk = identity collapses the ElGamal
// masking term and exposes the confidential derived key to the coordinator.
if bool::from(app_pk.is_identity()) {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the pattern already used in `robust_ecdsa/sign.rs` for `msg_hash`: [4](#0-3) 

---

### Proof of Concept

1. Caller invokes `ckd(participants, coordinator, me, key_pair, app_id, G1Projective::identity(), rng)`.
2. Inside `compute_signature_share`, `big_c = big_s + identity * y = big_s = x_i · H(pk ‖ app_id)`.
3. The coordinator aggregates: `total_big_c = Σ λ_i · x_i · H(pk ‖ app_id) = msk · H(pk ‖ app_id)`.
4. The coordinator reads `ckd_output.big_c()` and obtains the confidential derived key directly — no `app_sk` needed, no cryptographic work required. [5](#0-4)

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

**File:** src/confidential_key_derivation/mod.rs (L43-56)
```rust
    pub fn big_y(&self) -> ElementG1 {
        self.big_y
    }

    /// Outputs `big_c`
    pub fn big_c(&self) -> ElementG1 {
        self.big_c
    }

    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( `app_id` )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```
