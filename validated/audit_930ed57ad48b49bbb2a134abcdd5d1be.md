### Title
Missing Validation of `app_pk` Allows Coordinator to Learn Confidential Derived Secret via Identity-Point Substitution — (`File: src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` entry point accepts the caller-supplied ElGamal public key `app_pk: PublicKey` without validating that it is a non-identity point on G1. When `app_pk` is the G1 identity element, the ElGamal encryption term `y · A` collapses to the identity, causing each participant's ciphertext share `C_i` to equal their raw BLS signature share `S_i`. The coordinator, who aggregates all shares, then directly observes `C = msk · H(pk ‖ app_id)` — the confidential derived secret — in the clear, violating the core secrecy guarantee of the CKD protocol.

---

### Finding Description

The CKD protocol encrypts each node's BLS signature share under the app's ElGamal public key `A` so that only the app (holding the corresponding secret `a`) can unmask the final output. The encryption step in `compute_signature_share` is:

```
C_i = S_i + y_i · A
```

where `S_i = x_i · H(pk ‖ app_id)` is the secret BLS share contribution.

The public entry point `ckd()` performs several structural checks (duplicate participants, self-membership, coordinator membership) but performs **no validation on `app_pk`**: [1](#0-0) 

Inside `compute_signature_share`, `app_pk` is used directly in the encryption step with no guard: [2](#0-1) 

`PublicKey` is a type alias for `blstrs::G1Projective`: [3](#0-2) 

`G1Projective::identity()` is a valid Rust value that can be constructed and passed directly to `ckd()` without going through any deserialization path. Although `BLS12381G1Group::deserialize` does reject the identity: [4](#0-3) 

…this guard is only exercised when the point is decoded from bytes. A caller who constructs `ElementG1::identity()` in code, or whose MPC node software passes the identity received from the network without re-serializing it through this path, bypasses the check entirely.

When `app_pk = G1::identity()`:

- `app_pk * y.0 = identity` (scalar multiplication of the identity is always the identity)
- `big_c = big_s + identity = big_s = x_i · H(pk ‖ app_id)`
- `norm_big_c = λ_i · x_i · H(pk ‖ app_id)`

The coordinator aggregates in `do_ckd_coordinator`: [5](#0-4) 

Summing the normalized shares yields:

```
C = Σ λ_i · C_i = Σ λ_i · S_i = msk · H(pk ‖ app_id)
```

This is exactly the confidential key `s` (before HKDF), which the coordinator now holds in the clear.

---

### Impact Explanation

The CKD security requirement states that secrecy of `s` must hold even if individual MPC nodes are malicious:

> "Example values that should not be leaked even if a node is malicious are `s`, `msk` and private shares of other nodes" [6](#0-5) 

When `app_pk = identity`, the coordinator directly computes `C = msk · H(pk ‖ app_id)` and can derive `s = HKDF(C)`. This is a **critical disclosure of a confidential derived secret** — the exact value that the entire CKD protocol is designed to keep hidden from MPC nodes.

---

### Likelihood Explanation

The attack is reachable via two realistic paths:

1. **Malicious app**: An app submits `A = G1::identity()` as its ElGamal public key to the blockchain. The MPC node software receives this value and passes it to `ckd()` without re-validating it. The library accepts it silently. The coordinator learns `s` for that `app_id`.

2. **Malicious coordinator**: A coordinator who also controls the app (or intercepts the on-chain message) substitutes `A = identity` when invoking `ckd()` on their own node. Their own `C_coordinator = S_coordinator` is exposed, and if they can also observe the aggregated `C` (which they compute), they learn the full `msk · H(pk ‖ app_id)`.

No privileged key material is required. The `ckd()` API is the direct entry point and the missing check is a single missing identity test.

---

### Recommendation

Add an explicit identity check on `app_pk` at the start of `ckd()`, before the protocol is launched:

```rust
if app_pk.is_identity().into() {
    return Err(InitializationError::InvalidInput(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the guard already present in `BLS12381G1Group::deserialize` and closes the gap for callers who supply the point as a native Rust value rather than through deserialization. [7](#0-6) 

---

### Proof of Concept

```rust
use threshold_signatures::confidential_key_derivation::{
    ckd, AppId, ElementG1, KeygenOutput, SigningShare, VerifyingKey,
};
use blstrs::{G1Projective, G2Projective, Scalar};
use elliptic_curve::{Field, Group};

// Attacker supplies the G1 identity as app_pk
let malicious_app_pk = G1Projective::identity(); // A = 0·G1

// Normal protocol setup
let participants = /* ... */;
let coordinator = participants[0];
let me = coordinator;
let key_pair = KeygenOutput { public_key: pk, private_share: share };
let app_id = AppId::try_from(b"victim-app").unwrap();

// ckd() accepts identity without error
let protocol = ckd(
    &participants,
    coordinator,
    me,
    key_pair,
    app_id.clone(),
    malicious_app_pk,  // identity — no validation triggered
    rng,
).unwrap();

// After protocol completes, coordinator's CKDOutput.big_c equals
// msk · H(pk ‖ app_id) directly — the confidential key s is exposed.
// Coordinator computes: s = HKDF(ckd_output.big_c)
```

The root cause is at: [8](#0-7) 

with the missing guard in the public API at: [9](#0-8)

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

**File:** src/confidential_key_derivation/protocol.rs (L148-174)
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

**File:** docs/confidential_key_derivation/confidential-key-derivation.md (L113-118)
```markdown
- The *operator* is not trusted, but its TEE-enabled hardware is considered
  secure
- MPC nodes running in TEE: All are trusted and execute the protocol honestly.
  Liveness and correctness depend on this assumption, while the secrecy does
  not. Example values that should not be leaked even if a node is malicious of
  are $`s`$, $`\texttt{msk}`$ and private shares of other nodes
```
