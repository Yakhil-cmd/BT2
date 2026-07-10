### Title
Missing Identity-Point Validation on `app_pk` Allows Coordinator to Extract Confidential Derived Key - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `ckd()` entry point accepts the caller-supplied ElGamal public key `app_pk` (`PublicKey = blstrs::G1Projective`) without checking whether it is the group identity element. When a malicious requester submits `A = G1::identity()`, the ElGamal masking term `y_i · A` collapses to the identity for every participant, causing the coordinator to receive the raw BLS signature `msk · H(pk, app_id)` in the clear — the exact confidential key material the protocol is designed to hide from any single node.

### Finding Description

The `ckd()` function in `src/confidential_key_derivation/protocol.rs` validates participant lists and coordinator membership but performs **no validation on `app_pk`**: [1](#0-0) 

The value flows directly into `compute_signature_share()`: [2](#0-1) 

At line 174, each participant computes:

```
C_i = S_i + y_i · app_pk
```

When `app_pk = G1::identity()`, this reduces to:

```
C_i = S_i + y_i · identity = S_i = x_i · H(pk, app_id)
```

The coordinator then aggregates:

```
C = Σ λ_i · C_i = Σ λ_i · x_i · H(pk, app_id) = msk · H(pk, app_id)
```

This is the BLS threshold signature — the confidential key material — delivered to the coordinator in plaintext. The coordinator can immediately compute `s = HKDF(C)`.

The only identity check in the codebase is inside `verify_signature()` in `ciphersuite.rs`, which is called by the *app* after the fact to verify the output, not by the MPC nodes during protocol execution: [3](#0-2) 

No equivalent guard exists at the protocol entry point.

### Impact Explanation

The CKD security requirement is explicit: no single MPC node should be able to compute `s`, even if that node is the coordinator: [4](#0-3) 

With `app_pk = G1::identity()`, the coordinator receives `C = msk · H(pk, app_id)` directly and can derive `s = HKDF(C)` without the app's secret scalar `a`. This is a **Critical** disclosure of a confidential derived secret.

### Likelihood Explanation

`blstrs::G1Projective::identity()` is a valid, serializable Rust value. A malicious requester submits it on-chain as their ElGamal public key `A`. Every MPC node receives it from the blockchain and passes it verbatim to `ckd()`. No on-chain or off-chain validation is specified in the library to reject it. The attack requires only the ability to submit a CKD request — the documented unprivileged caller role.

### Recommendation

Add an explicit identity-point check in `ckd()` before the protocol starts:

```rust
use elliptic_curve::Group;

if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity point".to_string(),
    ));
}
```

This mirrors the pattern already used in `verify_signature()` and in the BLS group deserialization: [5](#0-4) 

### Proof of Concept

1. Malicious app constructs `app_pk = blstrs::G1Projective::identity()`.
2. App submits a CKD request on-chain with `(app_id, A = identity)`.
3. Each MPC node calls `ckd(..., app_pk = identity, ...)`. No error is returned.
4. In `compute_signature_share`, each node computes `big_c = big_s + identity * y = big_s = x_i · H(pk, app_id)`.
5. The coordinator sums the Lagrange-weighted shares: `C = msk · H(pk, app_id)`.
6. The coordinator's output `CKDOutput { big_y, big_c }` contains `big_c = msk · H(pk, app_id)` — the raw BLS signature.
7. The coordinator (or any colluding party) computes `s = HKDF(big_c)`, recovering the app's confidential derived key without ever knowing `a`. [6](#0-5) [7](#0-6)

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

**File:** src/confidential_key_derivation/ciphersuite.rs (L158-169)
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

**File:** src/confidential_key_derivation/ciphersuite.rs (L222-230)
```rust
) -> Result<(), frost_core::Error<BLS12381SHA256>> {
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
    }
```

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L113-118)
```markdown
- The *operator* is not trusted, but its TEE-enabled hardware is considered
  secure
- MPC nodes running in TEE: All are trusted and execute the protocol honestly.
  Liveness and correctness depend on this assumption, while the secrecy does
  not. Example values that should not be leaked even if a node is malicious of
  are $`s`$, $`\texttt{msk}`$ and private shares of other nodes
```
