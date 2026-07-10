### Title
Unvalidated `app_pk` in CKD Protocol Enables Malicious Coordinator to Decrypt Confidential Derived Key — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function accepts `app_pk` (the requester's ElGamal public key) as a caller-supplied parameter and passes it directly into the ElGamal encryption step inside `compute_signature_share`. The protocol never broadcasts `app_pk` through the protocol channel, never verifies cross-participant consistency of `app_pk`, and never binds `app_pk` to `app_id`. A malicious coordinator who controls the out-of-band distribution of `app_pk` to participants can substitute their own ElGamal public key. Because every participant encrypts their share under the coordinator-supplied `app_pk`, the coordinator can sum the received ciphertexts and decrypt the aggregate confidential key `msk · H(pk ‖ app_id)` using their own secret scalar — violating the protocol's core guarantee that no single party learns the secret.

---

### Finding Description

In `compute_signature_share` (lines 148–182 of `src/confidential_key_derivation/protocol.rs`), each participant computes:

```
hash_point = H(pk ‖ app_id)          // H is a random oracle over G1
big_s      = hash_point * x_i         // x_i = private share
y          = random scalar
big_y      = y * G
big_c      = big_s + app_pk * y       // ElGamal encryption of big_s under app_pk
```

The Lagrange-weighted pair `(λ_i · big_y, λ_i · big_c)` is sent privately to the coordinator. The coordinator sums all received pairs and returns `CKDOutput { big_y: Σ λ_i y_i G, big_c: Σ λ_i big_c_i }`.

The `app_pk` value used in line 174 (`big_c = big_s + app_pk * y.0`) is taken verbatim from the caller-supplied argument with no validation: [1](#0-0) 

The `ckd()` entry point performs participant-list and coordinator-presence checks but performs **no validation of `app_pk`** — it is forwarded unchanged into `run_ckd_protocol` and then into `compute_signature_share`: [2](#0-1) 

Critically, `app_pk` is never transmitted through the protocol channel (`SharedChannel`). There is no broadcast round where participants exchange and verify their `app_pk` values. Each participant blindly uses whatever `app_pk` was handed to it by the application layer — which in practice is the coordinator. [3](#0-2) 

---

### Impact Explanation

**Confidential derived key disclosure by a single malicious coordinator.**

Let the coordinator hold ElGamal keypair `(coord_sk, coord_pk)` where `coord_pk = coord_sk · G`.

**Attack steps:**

1. Requester sends `(app_id, app_pk_requester)` to the coordinator.
2. Malicious coordinator distributes `(app_id, coord_pk)` to every participant instead.
3. Each participant `i` computes `big_c_i = big_s_i + coord_pk · y_i` and sends `(λ_

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
