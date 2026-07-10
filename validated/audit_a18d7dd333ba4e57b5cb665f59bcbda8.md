### Title
Malicious Coordinator Can Supply Identity `app_pk` to Extract Confidential Derived Key - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD protocol accepts a caller-supplied `app_pk` (ElGamal encryption key) with no validation. A malicious coordinator who controls the distribution of `app_pk` to participants can supply the group identity element, causing the ElGamal blinding term to vanish and the aggregated output `C` to equal `msk · H(pk, app_id)` in the clear — the exact confidential derived secret the protocol is designed to protect.

### Finding Description
In `src/confidential_key_derivation/protocol.rs`, every participant (including the coordinator) calls `compute_signature_share`, which computes:

```
big_s  = x_i · H(pk ‖ app_id)          // private-share contribution
big_c  = big_s + app_pk · y             // ElGamal encryption of big_s
norm_big_c = big_c · λ_i
``` [1](#0-0) 

The coordinator then aggregates every participant's `norm_big_c`:

```
C = Σ norm_big_c_i = msk · H(pk ‖ app_id) + app_pk · Σ(λ_i · y_i · G)
``` [2](#0-1) 

The intended security property is that the coordinator cannot unmask `C` without the client's secret `app_sk`. This holds only when `app_pk` is a valid, unknown-discrete-log point. Neither `ckd()` nor `compute_signature_share` validates `app_pk` in any way — it is accepted as-is from the caller. [3](#0-2) 

If `app_pk` is the group identity `O`:

```
big_c  = big_s + O · y = big_s
C      = Σ λ_i · x_i · H(pk ‖ app_id) = msk · H(pk ‖ app_id)
```

The coordinator receives `msk · H(pk ‖ app_id)` directly in `C`, with no unmasking step required. The confidential derived key is fully disclosed.

### Impact Explanation
The output `msk · H(pk ‖ app_id)` is the confidential derived secret. The module's own documentation states the protocol "allows a client to derive a unique key for a specific application **without revealing** the application identifier to the key derivation service." [4](#0-3) 

Extracting this value breaks the core confidentiality guarantee. This maps directly to the allowed critical impact: **"Extraction, reconstruction, or disclosure of… confidential derived secrets."**

### Likelihood Explanation
**Low.** The attack requires a malicious coordinator. In a typical deployment the coordinator receives `app_pk` from the client and forwards it to all participants; a compromised coordinator can substitute the identity element before forwarding. No cryptographic break or external dependency failure is needed — only the coordinator's willingness to supply a crafted parameter.

### Recommendation
1. **Validate `app_pk` is not the identity** inside `ckd()` before the protocol starts:
   ```rust
   if app_pk.is_identity().into() {
       return Err(InitializationError::BadParameters(
           "app_pk must not be the group identity".into()));
   }
   ```
2. **Bind `app_pk` into the session transcript** (e.g., include it in the `session_id` hash) so that participants can detect disagreement on `app_pk` before contributing their private-share material.
3. Consider requiring participants to verify a proof of knowledge of `app_sk` corresponding to `app_pk`, preventing substitution with an arbitrary point whose discrete log is known to the coordinator.

### Proof of Concept
```
Setup: 3-of-3 CKD, honest participants P1, P2, P3; P1 is the (malicious) coordinator.

1. Client sends (app_id, app_pk_real) to coordinator P1.
2. P1 substitutes app_pk = O (identity) when calling ckd() for P2 and P3,
   and also uses app_pk = O for its own ckd() call.
3. Each participant computes:
     big_c_i = x_i · H(pk ‖ app_id) + O · y_i
             = x_i · H(pk ‖ app_id)
4. P1 aggregates:
     C = Σ λ_i · big_c_i = msk · H(pk ‖ app_id)
5. P1 reads msk · H(pk ‖ app_id) directly from C — no app_sk needed.
   The confidential derived key is fully extracted.
``` [5](#0-4)

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

**File:** src/confidential_key_derivation/mod.rs (L1-9)
```rust
//! Confidential Key Derivation (CKD) protocol.
//!
//! This module provides the implementation of the Confidential Key Derivation (CKD) protocol,
//! which allows a client to derive a unique key for a specific application without revealing
//! the application identifier to the key derivation service.
//!
//! The protocol is based on a combination of Oblivious Transfer (OT) and Diffie-Hellman key exchange.
//!
//! For more details, refer to the `confidential-key-derivation.md` document in the `docs` folder.
```
