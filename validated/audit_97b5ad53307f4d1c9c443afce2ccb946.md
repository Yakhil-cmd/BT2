### Title
Missing Validation of `app_pk` Identity Element in CKD Protocol Allows Coordinator to Extract Confidential Derived Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `ckd()` entry point accepts an `app_pk: PublicKey` (a BLS12-381 G1 point) without validating that it is not the group identity element. When `app_pk` is the identity, the ElGamal masking that protects the confidential derived key collapses, and the coordinator receives the unmasked secret `msk · H(pk ‖ app_id)` directly from the summed participant outputs.

### Finding Description
The CKD protocol is designed so that each participant computes a masked share:

```
big_s  = x_i · H(pk ‖ app_id)          // secret contribution
big_c  = big_s + app_pk · y             // masked with ephemeral y
big_y  = y · G
```

The coordinator sums the Lagrange-weighted shares:

```
total_C = Σ λ_i · big_c_i
        = Σ λ_i · x_i · H(pk ‖ app_id)  +  app_pk · Σ λ_i · y_i
        = msk · H(pk ‖ app_id)           +  app_pk · total_Y
```

When `app_pk = G1::identity()`, the second term vanishes:

```
total_C = msk · H(pk ‖ app_id)   (unmasked)
```

The coordinator now holds the confidential derived key directly, without ever needing `app_sk` to call `unmask()`.

The `ckd()` function performs several input checks (participant count, duplicates, self-membership, coordinator membership) but contains no guard against the identity element for `app_pk`: [1](#0-0) 

The vulnerable computation in `compute_signature_share` is: [2](#0-1) 

The coordinator aggregation that yields the unmasked key when `app_pk = identity`: [3](#0-2) 

### Impact Explanation
A malicious coordinator who controls or influences the `app_pk` value passed to each participant (e.g., by acting as the party that distributes protocol parameters) can supply `ElementG1::identity()`. Every participant's `big_c` then equals their unmasked `big_s`, and the coordinator's aggregation directly reconstructs `msk · H(pk ‖ app_id)` — the confidential derived key — without possessing `app_sk`. This matches the allowed critical impact: **disclosure of confidential derived secrets**.

### Likelihood Explanation
The `app_pk` is an externally supplied parameter with no type-level or runtime constraint preventing the identity element. In deployments where the coordinator is also the entity that distributes `app_pk` to participants (a common architecture for a coordinator-driven MPC service), a single malicious or compromised coordinator can trivially trigger this path. The attack requires no cryptographic break and no interaction beyond a single protocol invocation.

### Recommendation
Add an explicit identity-element check in `ckd()` before constructing the protocol:

```rust
use elliptic_curve::Group;
if app_pk == ElementG1::identity() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the existing pattern used elsewhere in the codebase, such as the identity check on `big_r` during robust ECDSA presigning: [4](#0-3) 

### Proof of Concept

```rust
use blstrs::G1Projective;
use elliptic_curve::Group;

// Coordinator passes the G1 identity as app_pk to all participants
let malicious_app_pk = G1Projective::identity();

// Each participant calls ckd() with this app_pk.
// Inside compute_signature_share:
//   big_c = big_s + identity * y = big_s   (masking removed)
//   norm_big_c = lambda_i * x_i * H(pk || app_id)
//
// Coordinator sums norm_big_c across all participants:
//   total_C = sum(lambda_i * x_i) * H(pk || app_id)
//           = msk * H(pk || app_id)   <-- confidential derived key, unmasked
//
// unmask(0) == total_C directly, no app_sk needed.
let protocol = ckd(
    &participants,
    coordinator,
    me,
    key_pair,
    app_id,
    malicious_app_pk,  // identity element — no validation rejects this
    rng,
).unwrap();
```

The coordinator obtains `CKDOutput` where `big_c = msk · H(pk ‖ app_id)` and can call `ckd_output.unmask(Scalar::ZERO)` to recover the confidential derived key without ever possessing the legitimate `app_sk`. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L50-57)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/confidential_key_derivation/protocol.rs (L66-101)
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
```

**File:** src/confidential_key_derivation/protocol.rs (L173-175)
```rust
    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L226-232)
```rust
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
