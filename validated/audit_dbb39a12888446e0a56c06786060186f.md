### Title
Missing Identity-Element Validation on `app_pk` Bypasses ElGamal Masking in CKD, Disclosing Confidential Derived Secret - (File: `src/confidential_key_derivation/protocol.rs`)

### Summary
The `ckd()` public API in `src/confidential_key_derivation/protocol.rs` accepts `app_pk: PublicKey` (a `blstrs::G1Projective` point) from the caller without checking whether it is the group identity element. The ElGamal masking step `C_i = S_i + y_i * A` reduces to `C_i = S_i` when `A` is the identity, causing the aggregated coordinator output `C` to equal `msk * H(pk, app_id)` — the confidential derived secret — in plaintext. A malicious caller who supplies `app_pk = G1Projective::identity()` receives the confidential derived key directly without possessing the corresponding private scalar `a`.

### Finding Description

The CKD protocol is designed as an ElGamal encryption scheme. Each participant computes:

```
S_i = x_i * H(pk || app_id)
C_i = S_i + y_i * A          // A = app_pk, the caller-supplied public key
```

The coordinator aggregates:

```
C = Σ λ_i * C_i = msk * H(pk || app_id) + (Σ λ_i * y_i) * A
```

The masking term `(Σ λ_i * y_i) * A` is what hides `msk * H(pk || app_id)` from anyone who does not know `a`. The app recovers the secret as `s = C − a * Y`.

The root cause is in `ckd()`: [1](#0-0) 

`app_pk` is passed through all validation checks (participant count, duplicates, self-presence, coordinator-presence) and forwarded directly to `compute_signature_share()` with no identity check: [2](#0-1) 

Specifically at line 174:

```rust
let big_c = big_s + app_pk * y.0;
```

When `app_pk = G1Projective::identity()`, `app_pk * y.0 = identity`, so `big_c = big_s`. Every participant sends `(λ_i * Y_i, λ_i * S_i)` to the coordinator. The coordinator aggregates: [3](#0-2) 

yielding `C = msk * H(pk || app_id)` — the BLS signature / confidential derived key — with no masking. The `PublicKey` type alias provides no protection: [4](#0-3) 

`blstrs::G1Projective` freely represents the identity element; the library imposes no newtype invariant excluding it.

### Impact Explanation

The confidential derived secret `s = msk * H(pk || app_id)` is disclosed directly in the CKD output `C` to any caller who passes `app_pk = G1Projective::identity()`. The entire security guarantee of the CKD protocol — that no single party (including the coordinator) learns `s` without the TEE app's private scalar `a` — is nullified. This matches the allowed Critical impact: **disclosure of confidential derived secrets**.

### Likelihood Explanation

`ckd()` is a public library function. Any integrator or malicious participant who controls the `app_pk` argument (e.g., a malicious developer contract forwarding a crafted `A` to the MPC network, or a direct library caller) can trigger this with a single call. No privileged access, leaked keys, or cryptographic breaks are required. The identity element is a valid, constructible `G1Projective` value in `blstrs`.

### Recommendation

Add an explicit identity-element check on `app_pk` at the entry point of `ckd()`, before the protocol is launched:

```rust
if bool::from(app_pk.is_identity()) {
    return Err(InitializationError::BadParameters(
        "app_pk must not be the identity element".to_string(),
    ));
}
```

This mirrors the existing `msg_hash == 0` guard in the robust ECDSA signing path: [5](#0-4) 

### Proof of Concept

```rust
use blstrs::{G1Projective, Group};
use threshold_signatures::confidential_key_derivation::{
    protocol::ckd, AppId, CKDOutputOption, ElementG1,
};
// ... setup participants, keygen_output, rng as normal ...

let malicious_app_pk = G1Projective::identity(); // identity element, no private key needed

let protocol = ckd(
    &participants,
    coordinator,
    me,
    keygen_output,
    AppId::try_from(b"victim_app").unwrap(),
    malicious_app_pk,  // <-- identity: bypasses ElGamal masking
    rng,
).unwrap();

// Run protocol; coordinator output C == msk * H(pk || app_id) directly.
// Attacker reads C from CKDOutput::big_c() without knowing any private scalar.
```

The coordinator's `CKDOutput::big_c()` will equal `msk * H(pk || app_id)` — the confidential derived key — with no masking applied, because `compute_signature_share` at line 174 computes `big_c = big_s + identity * y = big_s`. [6](#0-5)

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

**File:** src/confidential_key_derivation/mod.rs (L62-63)
```rust
pub type PublicKey = ElementG1;
pub type Signature = ElementG1;
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L91-95)
```rust
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }
```
