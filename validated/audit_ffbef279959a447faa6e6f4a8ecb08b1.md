### Title
Missing Threshold Validation in `ckd()` Allows Corrupted CKD Output When Fewer Than Threshold Participants Are Used — (`src/confidential_key_derivation/protocol.rs`)

---

### Summary

The `ckd()` function in `src/confidential_key_derivation/protocol.rs` performs several participant-set sanity checks but is entirely missing a threshold validation that exists in every analogous signing function in the codebase. Because `ckd()` does not accept a threshold parameter and does not verify that `participants.len() >= threshold`, a malicious or erroneous caller can run the CKD protocol with fewer participants than the reconstruction threshold, causing the coordinator to produce and return a silently incorrect derived key.

---

### Finding Description

Every other multi-party signing entry-point in the library explicitly validates that the participant count satisfies the threshold before the protocol begins.

**OT-based ECDSA `sign()`** — `src/ecdsa/ot_based_ecdsa/sign.rs` lines 57–63:

```rust
// ensure number of participants during the signing phase is >= threshold
if participants.len() < threshold {
    return Err(InitializationError::NotEnoughParticipantsForThreshold {
        threshold,
        participants: participants.len(),
    });
}
``` [1](#0-0) 

**Robust ECDSA `sign()`** — `src/ecdsa/robust_ecdsa/sign.rs` lines 67–82 — performs the equivalent check via `robust_ecdsa_threshold > participants.len()`. [2](#0-1) 

**`ckd()`** — `src/confidential_key_derivation/protocol.rs` lines 66–116 — performs four checks (minimum 2 participants, no duplicates, self present, coordinator present) but **never checks that `participants.len() >= threshold`**. Critically, `ckd()` does not even accept a threshold parameter, so the check is structurally impossible without a signature change. [3](#0-2) 

The CKD `KeygenOutput` type (used as `key_pair`) carries only `public_key` and `private_share` — no threshold field — confirming that the threshold established during DKG is completely lost by the time `ckd()` is called. [4](#0-3) 

Inside `compute_signature_share`, each participant computes their normalized share via Lagrange interpolation over the supplied `participants` list:

```rust
let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
let norm_big_y = big_y * lambda_i;
let norm_big_c = big_c * lambda_i;
``` [5](#0-4) 

When the participant list is smaller than the DKG threshold, the Lagrange coefficients are computed over the wrong domain. The coordinator then sums these malformed shares:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
Ok(Some(ckd_output))
``` [6](#0-5) 

The coordinator returns this incorrect `CKDOutput` with no downstream verification that the result equals the expected threshold BLS evaluation. The TEE application that calls `ckd_output.unmask(app_sk)` will silently receive the wrong derived secret.

---

### Impact Explanation

**High** — Corruption of CKD outputs so honest parties accept an unusable (wrong) cryptographic output. The coordinator produces and returns a `CKDOutput` that does not correspond to the correct threshold BLS evaluation of `msk · H(pk ‖ app_id)`. Any TEE application relying on this output will derive the wrong confidential key, breaking the security guarantee of the CKD protocol. There is no post-hoc verification step that would detect the corruption.

---

### Likelihood Explanation

Any caller of `ckd()` — including a malicious participant acting as coordinator — can supply a `participants` slice shorter than the DKG threshold. No privilege beyond being a valid participant is required. The missing parameter means there is no API-level barrier to this mistake or attack. The attack is deterministic and requires no cryptographic capability.

---

### Recommendation

1. Add a `threshold: impl Into<ReconstructionLowerBound>` parameter to `ckd()`, mirroring the signature of `sign()` in both ECDSA variants.
2. Add the guard immediately after the existing participant-count checks:

```rust
if participants.len() < threshold.value() {
    return Err(InitializationError::NotEnoughParticipantsForThreshold {
        threshold: threshold.value(),
        participants: participants.len(),
    });
}
```

3. Alternatively, store the threshold inside `KeygenOutput` for CKD so it can be validated without requiring callers to supply it separately.

---

### Proof of Concept

1. Run DKG with 3 participants and threshold 2, producing `KeygenOutput` for each.
2. Call `ckd()` with a `participants` slice containing only 1 participant (above the `< 2` guard but below threshold 2). The function accepts the call.
3. `compute_signature_share` computes `lambda_i` as the Lagrange coefficient for a 1-participant set (i.e., `lambda_i = 1`), not the correct coefficient for the 3-participant DKG.
4. The coordinator sums a single malformed share and returns a `CKDOutput`.
5. `ckd_output.unmask(app_sk)` yields a value that does not equal `msk · H(pk ‖ app_id)`, silently corrupting the derived key.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L57-63)
```rust
    // ensure number of participants during the signing phase is >= threshold
    if participants.len() < threshold {
        return Err(InitializationError::NotEnoughParticipantsForThreshold {
            threshold,
            participants: participants.len(),
        });
    }
```

**File:** src/ecdsa/robust_ecdsa/sign.rs (L67-82)
```rust
    // ensure number of participants during the signing phase is >= 2 * max_malicious + 1
    let robust_ecdsa_threshold = max_malicious
        .into()
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*threshold+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }
```

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

**File:** src/confidential_key_derivation/protocol.rs (L148-181)
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
```
