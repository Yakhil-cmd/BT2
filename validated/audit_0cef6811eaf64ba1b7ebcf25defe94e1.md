### Title
Missing Identity Element Validation for `app_pk` in CKD Protocol Causes Confidential Key Disclosure — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function accepts an `app_pk: PublicKey` (the application's ElGamal public key) without checking whether it is the group identity element. When `app_pk` is the identity, the ElGamal masking in `compute_signature_share` collapses entirely, causing the coordinator's aggregated output `big_c` to equal the raw confidential derived key `msk · H(pk, app_id)` in plaintext — directly readable from the protocol output without knowledge of `app_sk`.

---

### Finding Description

The CKD protocol is an ElGamal-style threshold encryption scheme. Each participant computes:

```
big_y = y · G
big_s = x_i · H(pk, app_id)          // share of the confidential key
big_c = big_s + app_pk · y            // ElGamal ciphertext share
```

The coordinator aggregates Lagrange-weighted shares:

```
sum_Y = Σ λ_i · big_y_i
sum_C = Σ λ_i · big_c_i
```

The application then recovers the confidential key as `sum_C − app_sk · sum_Y = msk · H(pk, app_id)`.

The masking term `app_pk · y` is the entire security of this scheme. If `app_pk` is the identity element `O`, then `app_pk · y = O` for any scalar `y`, so:

```
big_c = big_s + O = big_s = x_i · H(pk, app_id)
```

After Lagrange interpolation by the coordinator:

```
sum_C = Σ λ_i · x_i · H(pk, app_id) = msk · H(pk, app_id)
```

This is the confidential derived key itself, exposed in plaintext in the CKD output. No knowledge of `app_sk` is required to read it.

The `ckd()` entry point performs several input checks (participant count, duplicates, self-membership, coordinator membership) but performs **no check** that `app_pk` is a valid non-identity group element: [1](#0-0) 

The vulnerable computation is in `compute_signature_share`: [2](#0-1) 

Specifically, line 174 (`let big_c = big_s + app_pk * y.0;`) is the masking step that silently degenerates when `app_pk` is the identity. [3](#0-2) 

By contrast, the codebase does validate identity elements in other contexts — for example, the `dlogeq` prover and verifier both explicitly reject identity generators: [4](#0-3) 

And the BLS12-381 group deserialization rejects identity points: [5](#0-4) 

No equivalent guard exists at the `ckd()` API boundary for `app_pk`.

---

### Impact Explanation

**Critical — Extraction/disclosure of confidential derived secrets.**

When `app_pk = identity`, the coordinator's `CKDOutput` field `big_c` directly equals `msk · H(pk, app_id)` — the confidential derived key that the protocol is designed to protect. Any party that observes the coordinator's output (including the coordinator itself) can read the confidential key without possessing `app_sk`. The ElGamal confidentiality guarantee is completely voided.

---

### Likelihood Explanation

The `app_pk` is a caller-supplied parameter to the public `ckd()` API. A malicious application, a misconfigured integration, or a malicious coordinator that distributes `app_pk = identity` to all participants causes all participants to compute with a broken masking term. Because the protocol does not broadcast or cross-check `app_pk` among participants, there is no in-protocol mechanism to detect this. The attack requires only that the caller supply the identity element — a single-parameter substitution with no cryptographic barrier.

---

### Recommendation

Add an explicit identity-element check for `app_pk` at the start of `ckd()`, before the protocol is launched:

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
    // Reject identity app_pk — masking collapses to zero, exposing the confidential key
    if bool::from(app_pk.is_identity()) {
        return Err(InitializationError::BadParameters(
            "app_pk must not be the identity element".to_string(),
        ));
    }
    // ... existing checks ...
}
```

This mirrors the pattern already used in `dlogeq::prove_with_nonce` and `dlogeq::verify`.

---

### Proof of Concept

```rust
// Attacker supplies app_pk = identity to all participants
let app_pk = ElementG1::identity(); // the zero/identity point

// All participants run ckd() with this app_pk
// compute_signature_share computes:
//   big_c = big_s + identity * y = big_s   (masking term vanishes)
//   norm_big_c = big_s * lambda_i

// Coordinator aggregates:
//   sum_C = Σ λ_i * big_s_i = msk * H(pk, app_id)
//         = the confidential derived key in plaintext

// The CKDOutput.big_c field now directly contains the confidential key.
// No app_sk is needed to read it.
let ckd_output = /* coordinator's output */;
let confidential_key_leaked = ckd_output.big_c(); // = msk * H(pk, app_id)
```

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

**File:** src/crypto/proofs/dlogeq.rs (L114-116)
```rust
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
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
