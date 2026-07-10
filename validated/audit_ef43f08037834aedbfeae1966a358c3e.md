### Title
Missing Lower-Bound Threshold Validation in FROST `assert_sign_inputs` Allows Signing with Threshold < 2 - (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` in `src/frost/mod.rs` validates that the threshold does not exceed the participant count, but omits the lower-bound check (`threshold >= 2`) that every other threshold-accepting function in the codebase enforces. A caller or malicious coordinator can supply `threshold = 0` or `threshold = 1`, bypassing the minimum security requirement and causing the FROST signing protocol to run with a degenerate threshold, producing an unusable or cryptographically incorrect signature output.

### Finding Description
`assert_sign_inputs` performs the following threshold checks:

```rust
// src/frost/mod.rs lines 144-150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [1](#0-0) 

There is no corresponding lower-bound check. Compare this to `assert_key_invariants` in `src/dkg.rs`, which enforces both bounds:

```rust
// src/dkg.rs lines 573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [2](#0-1) 

The same dual-bound pattern is also enforced in `validate_triple_inputs` for Beaver triple generation: [3](#0-2) 

The `presign` function in the same file has the identical gap — it checks the upper bound on `args.threshold` but not the lower bound: [4](#0-3) 

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforcement of its own, so any value including 0 or 1 passes through: [5](#0-4) 

### Impact Explanation
With `threshold = 1`, the FROST signing protocol proceeds with a single participant's Lagrange-interpolated share. Because the key was distributed under a higher threshold during DKG, the single-share Lagrange reconstruction does not recover the master secret; the aggregated signature will not verify against the master public key. Honest participants expend nonce material and signature shares, and the coordinator returns a cryptographically unusable output. This matches the **High** impact class: *corruption of sign outputs so honest parties accept unusable cryptographic outputs*.

With `threshold = 0`, the Lagrange interpolation over an empty participant set will produce an arithmetic error or panic inside the protocol, causing an uncontrolled abort.

### Likelihood Explanation
The entry path is the public `assert_sign_inputs` API, callable by any application-layer coordinator. No special privilege beyond being the coordinator is required. The coordinator is an explicitly modeled adversary in this library's trust model. The missing check is a single-line omission that is inconsistent with every other threshold-accepting function in the codebase, making accidental or deliberate misuse realistic.

### Recommendation
Add the same lower-bound guard that `assert_key_invariants` and `validate_triple_inputs` already enforce:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same fix to the `presign` function in `src/frost/mod.rs` where `args.threshold` is validated.

### Proof of Concept
1. Call `assert_sign_inputs` with a valid participant list of size ≥ 2, `threshold = 1`, and valid `me`/`coordinator` values.
2. Observe that the function returns `Ok(participants)` — no error is raised.
3. Proceed to run the FROST signing protocol with `threshold = 1`.
4. The protocol completes, but the aggregated signature fails external verification against the master public key because only one Lagrange-weighted share was used instead of the required quorum.
5. Contrast with calling `assert_key_invariants` with `threshold = 1`, which immediately returns `Err(InitializationError::ThresholdTooSmall { threshold: 1, min: 2 })`. [6](#0-5) [7](#0-6)

### Citations

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

**File:** src/frost/mod.rs (L119-159)
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
```

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L692-704)
```rust
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
