### Title
Missing `me ∈ participants` Validation in Triple Generation Entry Points — (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`)

### Summary

Every public protocol entry point in the library validates that the calling party (`me`) is a member of the supplied participant list before proceeding. The sole exception is `generate_triple` / `generate_triple_many`, whose shared validation helper `validate_triple_inputs` omits this check entirely. A caller (or a malicious coordinator who supplies the participant list) can therefore cause triple generation to proceed with `me` absent from the participant set, producing a structurally invalid triple share. That share is silently accepted by the subsequent `presign` entry point (which explicitly skips participant-set consistency checks against the triple), resulting in a corrupted presignature and permanent signing failure for the affected honest party.

---

### Finding Description

`generate_triple` and `generate_triple_many` both delegate all input validation to `validate_triple_inputs`:

```rust
// src/ecdsa/ot_based_ecdsa/triples/generation.rs  lines 681-708
fn validate_triple_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    // checks: len >= 2, threshold <= len, threshold >= 2, no duplicates
    // *** NO check that `me` is in `participants` ***
}
``` [1](#0-0) 

Both public wrappers pass `me` directly to `do_generation` without any membership guard:

```rust
pub fn generate_triple(
    participants: &[Participant],
    me: Participant,          // ← accepted but never validated against `participants`
    threshold: ...,
    rng: ...,
) -> Result<...> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}
``` [2](#0-1) 

Every other protocol entry point in the library performs this check explicitly. The DKG helper `assert_key_invariants` is representative:

```rust
// src/dkg.rs  lines 588-594
if !participants.contains(me) {
    return Err(InitializationError::MissingParticipant {
        role: "self",
        participant: me,
    });
}
``` [3](#0-2) 

The same guard appears in OT-based `presign`, robust `presign`, OT-based `sign`, robust `sign`, FROST `presign`, and `ckd`: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

The downstream `presign` entry point explicitly documents that it does **not** re-validate participant-set consistency against the triple:

```rust
// NOTE: We omit the check that the new participant set was present for
// the triple generation, because presumably they need to have been present
// in order to have shares.
``` [9](#0-8) 

This means a triple produced with `me ∉ participants` passes all presign entry-point checks and is used as-is.

---

### Impact Explanation

When `me` is absent from the participant list supplied to `generate_triple`, `do_generation` executes with `me` as an unregistered identity. `recv_from_others` collects shares from every listed participant (none of which is `me`), and `me`'s own polynomial is evaluated at participant identifiers that do not include `me`'s scalar. The resulting `TripleGenerationOutput` held by `me` contains a share that does not lie on the shared polynomial at any valid evaluation point. When this triple is consumed by `presign`, the presignature is cryptographically inconsistent. The coordinator's `do_sign_coordinator` then fails at the final verification step:

```rust
if !sig.verify(&public_key, &msg_hash) {
    return Err(ProtocolError::AssertionFailed("signature failed to verify".to_string()));
}
``` [10](#0-9) 

The honest party holding the corrupted triple cannot produce a valid signature for any message. This matches the allowed impact: **High — Corruption of presign outputs / Permanent denial of signing for honest parties**.

---

### Likelihood Explanation

The attack surface is realistic. In a deployed MPC system the coordinator is responsible for assembling and distributing the participant list for each session. A malicious coordinator can trivially omit a target honest party's own identifier from the list it sends to that party while keeping it in the lists sent to all other parties. The honest party calls `generate_triple` with `me` absent from `participants`, receives no `InitializationError` (unlike every other protocol), and silently produces a corrupted triple. The inconsistency with all other entry points means library users and auditors have no reason to expect this gap.

---

### Recommendation

Add the `me ∈ participants` membership check to `validate_triple_inputs`, mirroring the pattern used uniformly everywhere else:

```rust
fn validate_triple_inputs(
    participants: &[Participant],
    me: Participant,                          // add `me` parameter
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    // ... existing checks ...
    let participants = ParticipantList::new(participants)
        .ok_or(InitializationError::DuplicateParticipants)?;
    if !participants.contains(me) {           // add this guard
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok((participants, threshold))
}
```

Apply the same fix to `generate_triple_many`. This aligns triple generation with the uniform validation contract established by every other protocol entry point in the library. [11](#0-10) 

---

### Proof of Concept

1. Honest party `P1` (id = `Participant(1)`) is told by a malicious coordinator to run triple generation with participant list `[Participant(2), Participant(3)]` (omitting `Participant(1)`).
2. `P1` calls `generate_triple(&[Participant(2), Participant(3)], Participant(1), threshold, rng)`.
3. `validate_triple_inputs` succeeds — no `me ∈ participants` check exists.
4. `do_generation` runs with `me = Participant(1)` absent from the participant list. `P1`'s triple share is computed at an evaluation point not in the polynomial's domain.
5. `P1` stores the resulting `TripleGenerationOutput` and later calls `presign` with it. `presign` skips participant-set consistency checks against the triple (per the explicit comment at line 38–40).
6. The presignature produced by `P1` is cryptographically invalid. The coordinator's signing step fails at `sig.verify(...)`, returning `ProtocolError::AssertionFailed`. Signing is permanently blocked for `P1` until new triples are generated — which the malicious coordinator can repeat indefinitely.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L681-708)
```rust
fn validate_triple_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<(ParticipantList, ReconstructionLowerBound), InitializationError> {
    let threshold = threshold.into();
    let threshold_value = threshold.value();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if threshold_value > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold_value,
            max: participants.len(),
        });
    }
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;
    Ok((participants, threshold))
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L717-727)
```rust
pub fn generate_triple(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutput>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L729-740)
```rust
/// As [`generate_triple`] but for many triples at once
pub fn generate_triple_many<const N: usize>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutputMany>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation_many::<N>(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/dkg.rs (L588-594)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L38-40)
```rust
    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L52-57)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/robust_ecdsa/presign.rs (L45-50)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L41-47)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/ecdsa/ot_based_ecdsa/sign.rs (L129-132)
```rust
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
```

**File:** src/confidential_key_derivation/protocol.rs (L87-93)
```rust
    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```

**File:** src/frost/mod.rs (L64-69)
```rust
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```
