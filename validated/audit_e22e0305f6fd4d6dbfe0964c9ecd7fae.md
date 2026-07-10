### Title
Missing Lower-Bound Threshold Validation in FROST Signing Entry Point Allows Corrupted Sign Outputs — (File: `src/frost/mod.rs`)

---

### Summary

The `assert_sign_inputs` function in `src/frost/mod.rs` validates that the signing threshold does not *exceed* the participant count, but omits the lower-bound check (`threshold < 2`) that is explicitly present in the DKG entry point `assert_key_invariants` in `src/dkg.rs`. Because `ReconstructionLowerBound` does not enforce a minimum of 2 at the type level, a malicious or misconfigured caller can invoke the FROST signing protocol with `threshold = 1`, causing the protocol to proceed with incorrect Lagrange coefficients and produce an invalid, unusable signature.

---

### Finding Description

`assert_key_invariants` (the DKG entry-point guard) enforces both an upper and a lower bound on the threshold: [1](#0-0) 

```rust
// Step 1.1
// validate threshold
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// Step 1.1
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

`assert_sign_inputs` (the FROST signing entry-point guard) enforces only the upper bound and silently accepts any value ≥ 1 (or even 0 if the type permits): [2](#0-1) 

```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    // ...
    // validate threshold — upper bound only
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge { ... });
    }
    // ← NO lower-bound check; threshold = 1 passes through
    Ok(participants)
}
```

The fact that `assert_key_invariants` explicitly checks `threshold < 2` after converting from `ReconstructionLowerBound` proves the type itself does not enforce the minimum: [3](#0-2) 

The same gap exists in the OT-based ECDSA presign entry point, which checks the upper bound but not the lower bound on `args.threshold`: [4](#0-3) 

---

### Impact Explanation

In FROST (and the OT-based ECDSA presign), the threshold governs Lagrange interpolation of secret shares. When `threshold = 1` is supplied at signing time but the key was generated with `threshold ≥ 2`:

- The Lagrange coefficient for a single participant evaluates to 1 (trivial), stripping the correct weighting applied during key generation.
- Each participant's signature share is computed against the wrong linear combination of the secret.
- The coordinator aggregates shares that are individually well-formed but collectively inconsistent with the aggregate public key.
- The resulting signature fails verification — an **unusable cryptographic output** delivered to honest parties who had no way to detect the bad threshold before the protocol ran.

This maps to the allowed High impact: *Corruption of sign outputs so honest parties accept inconsistent or unusable cryptographic outputs.*

---

### Likelihood Explanation

The threshold is a plain caller-supplied parameter with no type-level enforcement of the minimum. Any library consumer — including a malicious coordinator who orchestrates which threshold value is broadcast to participants, or a single misconfigured participant — can supply `threshold = 1` without triggering any error at the entry point. No special privilege, leaked key material, or cryptographic break is required.

---

### Recommendation

Mirror the lower-bound guard from `assert_key_invariants` into `assert_sign_inputs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same fix to the OT-based ECDSA `presign` entry point in `src/ecdsa/ot_based_ecdsa/presign.rs`.

Alternatively, encode the invariant at the type level in `ReconstructionLowerBound` so that construction with a value below 2 is a compile-time or construction-time error, making the guard unnecessary in every call site.

---

### Proof of Concept

1. Run DKG for 3 participants with `threshold = 2` (accepted; `assert_key_invariants` enforces ≥ 2).
2. Call the FROST signing function for the same 3 participants, passing `threshold = 1`.
3. `assert_sign_inputs` returns `Ok(participants)` — no error is raised.
4. The signing protocol executes; each participant computes a signature share using Lagrange coefficient 1 instead of the correct coefficient for `threshold = 2`.
5. The coordinator aggregates the shares and produces a signature that fails verification against the public key established during DKG.
6. Honest parties receive an unusable signature with no indication that the threshold mismatch was the cause.

### Citations

**File:** src/dkg.rs (L558-596)
```rust
pub fn assert_key_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
) -> Result<ParticipantList, InitializationError> {
    let threshold = usize::from(threshold.into());
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    // Step 1.1
    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }

    // ensure uniqueness of participants in the participant list
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
    Ok(participants)
}
```

**File:** src/frost/mod.rs (L120-160)
```rust
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
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

    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
}
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L24-57)
```rust
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.value(),
            max: participants.len(),
        });
    }

    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }
```
