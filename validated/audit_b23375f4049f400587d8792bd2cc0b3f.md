### Title
Missing Validation of Identity `app_pk` in CKD Protocol Discloses Confidential Derived Key to Coordinator — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` public entry point accepts `app_pk: PublicKey` (a `blstrs::G1Projective` point) without checking whether it is the group identity element. When `app_pk` is the identity, the ElGamal blinding term `app_pk * y` collapses to the identity, stripping the mask from every participant's `big_c` share. The coordinator then aggregates an unmasked `big_c = msk · H(pk ‖ app_id)` — the confidential derived key — directly, violating the core CKD security property.

---

### Finding Description

In `compute_signature_share`, each participant computes:

```
big_c = big_s + app_pk * y
      = (x_i · H(pk, app_id)) + app_pk · y
``` [1](#0-0) 

When `app_pk` is the group identity `O`, scalar multiplication `O * y = O`, so:

```
big_c = x_i · H(pk, app_id)   (no blinding)
```

Each participant then normalises by their Lagrange coefficient and sends `(λ_i · big_y, λ_i · big_c)` to the coordinator. [2](#0-1) 

The coordinator sums all shares:

```
big_c_total = Σ λ_i · x_i · H(pk, app_id) = msk · H(pk, app_id)
``` [3](#0-2) 

This is the confidential derived key. The coordinator can recover it immediately by calling `unmask(0)`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar   // = big_c - 0 = msk·H(pk,app_id)
}
``` [4](#0-3) 

The `ckd()` initialisation block validates participant counts, duplicates, and coordinator membership, but performs **no check** on `app_pk`: [5](#0-4) 

---

### Impact Explanation

The CKD protocol's stated purpose is to let a client derive a key for an application **without revealing it to the key derivation service (coordinator)**. The ElGamal blinding `app_pk * y` is the sole mechanism that hides `msk · H(pk, app_id)` from the coordinator. Passing `app_pk = O` removes that blinding entirely: the coordinator receives the confidential derived secret in the clear, matching the Critical impact class **"disclosure of confidential derived secrets."**

---

### Likelihood Explanation

`app_pk` is a `blstrs::G1Projective` value supplied by the calling application. A default-initialised or zero-valued `G1Projective` in Rust is the identity element. Any application that forgets to set `app_pk`, initialises it from a zeroed buffer, or passes an uninitialised struct will silently trigger this path. The library offers no guard, no documentation warning, and no runtime error for this input.

---

### Recommendation

Add an identity-element check in `ckd()` before constructing the protocol:

```rust
if bool::from(app_pk.is_identity()) {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the group identity element".to_string(),
    ));
}
```

This mirrors the existing zero-scalar guard in `assert_keyshare_inputs` for DKG secrets. [6](#0-5) 

---

### Proof of Concept

```
Setup:
  app_sk = 0  (i.e. app_pk = O, the G1 identity)
  participants: [P1, P2, P3], coordinator = P1

Each participant i calls ckd(..., app_pk = O, ...):
  big_s_i = x_i · H(pk, app_id)
  big_c_i = big_s_i + O * y_i = big_s_i          ← no blinding
  sends (λ_i·big_y_i, λ_i·big_c_i) to coordinator

Coordinator aggregates:
  big_c = Σ λ_i · x_i · H(pk, app_id) = msk · H(pk, app_id)

Coordinator calls unmask(0):
  result = big_c - 0·big_y = msk · H(pk, app_id)  ← confidential key disclosed
```

The coordinator now holds the confidential derived key without possessing `app_sk`, breaking the CKD confidentiality guarantee.

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-56)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
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

**File:** src/confidential_key_derivation/protocol.rs (L171-174)
```rust
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/protocol.rs (L176-181)
```rust
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

**File:** src/dkg.rs (L48-53)
```rust
        if is_zero_secret {
            return Err(ProtocolError::AssertionFailed(format!(
                "{me:?} is running DKG with a zero share"
            )));
        }
        Ok((None, None))
```
