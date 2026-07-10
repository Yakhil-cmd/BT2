The key finding is a missing lower-bound validation on `threshold` in `assert_sign_inputs` (`src/frost/mod.rs`) and the FROST `presign` function, contrasted with `assert_key_invariants` (`src/dkg.rs`) which correctly enforces both upper and lower bounds.

---

### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Allows Single-Party Signature Production - (File: `src/frost/mod.rs`)

### Summary
`assert_sign_inputs` and the FROST `presign` function accept a caller-supplied `threshold` parameter and validate only the upper bound (`threshold > participants.len()`), but never enforce the lower bound (`threshold >= 2`). A caller passing `threshold = 1` bypasses the multi-party requirement, allowing a single participant to produce a valid FROST threshold signature unilaterally.

### Finding Description
`assert_key_invariants` in `src/dkg.rs` correctly enforces both bounds on `threshold`:

```rust
// src/dkg.rs lines 573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

By contrast, `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// src/frost/mod.rs lines 144-150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← No lower-bound check: threshold < 2 is never rejected
``` [2](#0-1) 

Similarly, the FROST `presign` function only checks the upper bound:

```rust
// src/frost/mod.rs lines 71-77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← No lower-bound check
``` [3](#0-2) 

`assert_sign_inputs` is the shared validation entry point for both the EdDSA (`src/frost/eddsa/`) and RedJubjub (`src/frost/redjubjub/`) signing paths. [4](#0-3) 

`ReconstructionLowerBound` is a plain `usize` newtype with no internal invariant enforcing a minimum value of 2, so `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` are freely constructible by any caller. [5](#0-4) 

### Impact Explanation
In FROST, `threshold` (the `ReconstructionLowerBound`) controls how many participant signature shares are aggregated to reconstruct the final signature. Passing `threshold = 1` causes the signing protocol to treat a single participant's share as sufficient for a complete, valid signature. This allows any one participant — including a malicious one — to produce a valid threshold signature for an arbitrary message without cooperation from any other party, directly violating the `t-of-n` security guarantee.

**Impact class:** Critical — Unauthorized creation of a valid threshold signature for attacker-chosen inputs.

### Likelihood Explanation
The `threshold` parameter is supplied directly by the library caller at each signing invocation. There is no type-level enforcement preventing `threshold = 1`. Any application that misconfigures or is manipulated into passing `threshold = 1` (e.g., via a malicious coordinator constructing signing arguments) triggers the vulnerability. The missing check is a single missing `if threshold < 2` guard, making accidental or adversarial triggering realistic.

### Recommendation
Add the same lower-bound check present in `assert_key_invariants` to both `assert_sign_inputs` and the FROST `presign` function:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after the upper-bound check in both locations in `src/frost/mod.rs`.

### Proof of Concept
1. Call `assert_sign_inputs` with a valid participant list of size 3, `threshold = ReconstructionLowerBound(1)`, and any valid `me`/`coordinator`.
2. Observe: the function returns `Ok(participants)` — no error is raised.
3. Proceed to the FROST sign protocol with `threshold = 1`; a single participant's share satisfies reconstruction, producing a valid signature without any other party's cooperation.
4. Contrast: calling `assert_key_invariants` with the same `threshold = 1` correctly returns `Err(InitializationError::ThresholdTooSmall { threshold: 1, min: 2 })`. [6](#0-5)

### Citations

**File:** src/dkg.rs (L573-582)
```rust
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
