### Title
Missing Identity Element Validation for `app_pk` in `ckd()` Allows Coordinator to Directly Recover Confidential Derived Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The `ckd()` entry point in `src/confidential_key_derivation/protocol.rs` accepts an `app_pk: PublicKey` (a `G1Projective` element) without validating that it is not the group identity element. If `app_pk` is the identity, the per-participant blinding term `y_i · A` collapses to zero, causing the aggregated `big_c` to equal `msk · H(pk ‖ app_id)` — the confidential derived key — in the clear. A coordinator who controls the `app_pk` value supplied to all participants can therefore recover the confidential key without possessing the application secret scalar `a`.

### Finding Description
The CKD blinding scheme works as follows. Each participant computes:

```
big_s  = x_i · H(pk ‖ app_id)
big_c  = big_s + app_pk · y_i          // blinding term: app_pk · y_i
norm_big_c = λ_i · big_c
```

The coordinator sums the normalized shares:

```
big_c_agg = Σ λ_i · (x_i · H(pk ‖ app_id) + y_i · A)
           = msk · H(pk ‖ app_id)  +  (Σ λ_i · y_i) · A
```

The client unmasks with `big_c_agg − a · big_y_agg = msk · H(pk ‖ app_id)`.

The blinding relies entirely on `A = app_pk` being a non-identity point. The `ckd()` initializer performs four checks (participant count, duplicates, self-membership, coordinator-membership) but **never checks** whether `app_pk` is the identity: [1](#0-0) 

Inside `compute_signature_share`, the blinding line is: [2](#0-1) 

When `app_pk = G1::identity()`:

```
big_c  = big_s + identity · y_i  =  big_s  =  x_i · H(pk ‖ app_id)
big_c_agg = msk · H(pk ‖ app_id)          // confidential key, unmasked
```

The coordinator's `CKDOutput.big_c` field now holds the confidential derived key directly. The `unmask()` helper is irrelevant; the coordinator already has the secret. [3](#0-2) 

The `BLS12381G1Group::serialize()` does reject the identity, but it is only called during wire serialization, not during the arithmetic in `compute_signature_share`. [4](#0-3) 

### Impact Explanation
A coordinator who supplies `app_pk = G1::identity()` to all participants (possible when the coordinator orchestrates the session and distributes protocol inputs) receives `CKDOutput { big_c = msk · H(pk ‖ app_id) }` — the confidential derived key — without ever knowing the application secret scalar `a`. This is a direct disclosure of a confidential derived secret, matching the Critical impact tier: *"Extraction, reconstruction, or disclosure of … confidential derived secrets."*

### Likelihood Explanation
The `app_pk` parameter is caller-supplied. In deployments where a single coordinator process assembles and distributes all protocol inputs to participant nodes (a common MPC orchestration pattern), the coordinator controls the `app_pk` value seen by every participant. Passing the identity element requires no cryptographic capability — it is a trivially constructable `G1Projective::identity()` value. The library provides no guard, so the attack is reachable with a single malformed input.

### Recommendation
Add an explicit identity-element check in `ckd()` before the protocol is launched:

```rust
// In ckd(), after the participant-list checks:
if app_pk.is_identity().into() {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the pattern already used in `BLS12381G1Group::serialize()` and in `dlogeq::prove_with_nonce` / `verify`, which both reject identity inputs before performing any cryptographic computation. [5](#0-4) 

### Proof of Concept

```rust
// Attacker (coordinator) supplies identity as app_pk to every participant.
use blstrs::G1Projective;
use elliptic_curve::Group;

let identity_pk = G1Projective::identity();   // the zero point

// All participants call ckd() with identity_pk.
// compute_signature_share produces:
//   big_c = x_i * H(pk || app_id) + identity * y_i
//         = x_i * H(pk || app_id)
// Coordinator aggregates:
//   big_c_agg = msk * H(pk || app_id)   ← confidential key, in the clear
//
// Coordinator reads ckd_output.big_c() directly — no unmask needed.
let confidential_key = ckd_output.big_c();   // == msk * H(pk || app_id)
```

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

**File:** src/confidential_key_derivation/protocol.rs (L173-174)
```rust
    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L194-200)
```rust
    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }
```

**File:** src/crypto/proofs/dlogeq.rs (L114-116)
```rust
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }
```
