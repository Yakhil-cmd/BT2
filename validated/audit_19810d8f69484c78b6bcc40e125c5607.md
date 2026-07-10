### Title
Missing Lower-Bound Threshold Validation in `assert_sign_inputs` Allows Threshold=1 Signing — (`src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates the upper bound of the signing threshold (`threshold > participants.len()`) but omits the lower-bound check (`threshold < 2`). This is the direct analog of the BondAggregator bug: one half of a two-part constraint is enforced while the other is silently skipped. A caller can pass `threshold = 1` (or `0`) to any FROST EdDSA or RedJubjub signing entry point, bypassing the minimum-threshold invariant that `assert_key_invariants` correctly enforces for DKG.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold:

```rust
// src/dkg.rs lines 573–582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs` only enforces the upper bound:

```rust
// src/frost/mod.rs lines 144–150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
// ← no check: threshold.value() < 2
``` [2](#0-1) 

The same omission exists in the `presign` entry point in the same file:

```rust
// src/frost/mod.rs lines 71–77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no built-in minimum:

```rust
// src/thresholds.rs lines 12–24
pub struct ReconstructionLowerBound(usize);
impl ReconstructionLowerBound {
    pub fn value(self) -> usize { self.0 }
}
``` [4](#0-3) 

There is nothing preventing a caller from constructing `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` and passing it to `assert_sign_inputs` or `frost::presign`. Both calls will pass all validation and proceed into the FROST signing rounds.

---

### Impact Explanation

FROST signing uses the threshold to compute Lagrange interpolation coefficients over the participant set. When the signing threshold is set to `1` (or `0`) but the key was generated with threshold `≥ 2`, the Lagrange reconstruction uses the wrong polynomial degree. The resulting aggregated signature share is cryptographically invalid — it does not correspond to the master public key. Honest participants complete the protocol and accept the output, but the produced signature is unusable and unverifiable. This constitutes **corruption of sign outputs so honest parties accept unusable cryptographic outputs**.

Mapped impact: **High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

`assert_sign_inputs` is a public library function. Any library caller constructing signing parameters controls the `threshold` argument directly. A misconfigured or malicious caller can trivially pass `threshold = 1`. There is no type-level or runtime guard preventing `ReconstructionLowerBound(1)` from being constructed and passed through. The missing check is a single missing `if` branch, identical in structure to the BondAggregator bug.

---

### Recommendation

Add the same lower-bound check that `assert_key_invariants` already enforces, immediately after the upper-bound check in `assert_sign_inputs` and in `frost::presign`:

```rust
// src/frost/mod.rs — assert_sign_inputs
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ADD:
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold: threshold.value(), min: 2 });
}
```

Apply the same fix to the `presign` function's threshold validation block at lines 71–77. [5](#0-4) 

---

### Proof of Concept

1. Key is generated with `threshold = 2`, `participants = [A, B, C]` via `assert_key_invariants` — this succeeds and enforces `threshold >= 2`.
2. Caller invokes `assert_sign_inputs(participants, ReconstructionLowerBound(1), me, coordinator)`.
3. Check `1 > 3` → false, no error. Check `participants.len() < 2` → false, no error. All other checks pass.
4. `assert_sign_inputs` returns `Ok(participants)`.
5. The FROST signing protocol runs with `threshold = 1`; Lagrange coefficients are computed for a degree-0 polynomial.
6. The aggregated signature is computed over the wrong polynomial degree and does not verify against the master public key generated at step 1.
7. Honest parties receive and accept a corrupted, unusable signature output. [6](#0-5) [7](#0-6)

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

**File:** src/frost/mod.rs (L71-77)
```rust
    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }
```

**File:** src/frost/mod.rs (L119-160)
```rust
/// Verifies that the sign inputs are valid
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

**File:** src/thresholds.rs (L12-24)
```rust
pub struct ReconstructionLowerBound(usize);

// ----- MaxMalicious conversions -----
impl MaxMalicious {
    pub fn value(self) -> usize {
        self.0
    }
}

impl ReconstructionLowerBound {
    pub fn value(self) -> usize {
        self.0
    }
```
