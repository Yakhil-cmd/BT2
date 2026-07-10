### Title
Missing Lower-Bound Validation on `threshold` in `assert_sign_inputs` Allows Signing with Threshold < 2 — (File: src/frost/mod.rs)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` validates signing inputs but omits the lower-bound check (`threshold >= 2`) that is explicitly enforced in `assert_key_invariants` in `src/dkg.rs`. A caller can pass `threshold = 1` or `threshold = 0` to the FROST signing entry point; the guard accepts it, the protocol proceeds with a cryptographically invalid threshold, and the resulting signing output is corrupted or unusable.

---

### Finding Description

`assert_key_invariants` (`src/dkg.rs`) enforces both bounds on the threshold:

```rust
// src/dkg.rs  lines 573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` (`src/frost/mod.rs`) only enforces the upper bound:

```rust
// src/frost/mod.rs  lines 144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [2](#0-1) 

There is no corresponding `threshold < 2` guard. The same omission exists in the FROST `presign` function:

```rust
// src/frost/mod.rs  lines 71-77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [3](#0-2) 

`ReconstructionLowerBound` and `MaxMalicious` are plain `usize` wrappers with no invariant enforcement at construction time, so any value including 0 or 1 can be passed in: [4](#0-3) 

---

### Impact Explanation

**High — Corruption of signing outputs so honest parties accept unusable cryptographic outputs.**

- **`threshold = 1`**: The FROST signing protocol collects shares and performs Lagrange interpolation assuming only 1 share is required. Because the key was generated with `threshold >= 2`, the interpolation is evaluated over the wrong polynomial degree. The aggregated signature scalar is incorrect; the resulting signature fails standard verification against the master public key. Every honest participant has invested communication rounds and produced a protocol transcript that yields an invalid, unusable signature.

- **`threshold = 0`**: Lagrange interpolation over zero points is undefined. Depending on the underlying `frost_core` implementation this either panics (aborting the signing session) or returns a zero/identity scalar, both of which constitute permanent denial of signing for that session.

In both cases the impact falls squarely within: *"Corruption of sign outputs so honest parties accept inconsistent or unusable cryptographic outputs"* and *"Permanent denial of signing for honest parties under valid protocol inputs."*

---

### Likelihood Explanation

**Medium.** The library is a Rust crate consumed by external callers. The `assert_sign_inputs` function is the documented validation gate before signing begins. A misconfigured integration (e.g., a coordinator that stores the threshold as a plain integer and accidentally passes `1` after a configuration change) or a malicious coordinator who deliberately supplies `threshold = 1` to sabotage a signing session can trigger this path without any privileged access. The keygen path is protected, but the signing path is not, creating an asymmetric and surprising gap.

---

### Recommendation

Add the lower-bound check to `assert_sign_inputs` in `src/frost/mod.rs`, mirroring `assert_key_invariants`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same guard to the `presign` function in the same file (after line 77). Consider centralising both bounds into a shared helper (e.g., `validate_threshold`) called from every protocol entry point so the invariant cannot be omitted again.

---

### Proof of Concept

```rust
// Passes assert_sign_inputs with threshold = 1, participants = [A, B]
// Both participants are valid, coordinator is valid, threshold (1) <= 2 — no error returned.
let participants = vec![participant_a, participant_b];
let result = assert_sign_inputs(
    &participants,
    ReconstructionLowerBound::from(1usize),  // threshold = 1, below minimum of 2
    participant_a,
    participant_b,
);
assert!(result.is_ok()); // passes — no ThresholdTooSmall error is raised

// The signing protocol then proceeds with threshold = 1.
// Lagrange interpolation uses only 1 share for a key generated with threshold = 2.
// The aggregated signature is cryptographically invalid.
``` [5](#0-4) [6](#0-5)

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

**File:** src/thresholds.rs (L9-24)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
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
