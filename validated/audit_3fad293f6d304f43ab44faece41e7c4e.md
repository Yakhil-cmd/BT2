### Title
Missing Lower-Bound Validation on `threshold` in `assert_sign_inputs` Allows Threshold-1 FROST Signing - (File: src/frost/mod.rs)

### Summary
`assert_sign_inputs` in `src/frost/mod.rs` validates the `threshold` parameter only against an upper bound (`threshold > participants.len()`), but omits the lower-bound check (`threshold >= 2`) that is explicitly enforced in the analogous DKG validation function `assert_key_invariants` in `src/dkg.rs`. A caller supplying `threshold = 1` (or `0`) passes all validation and proceeds into the FROST signing protocol with a degenerate threshold, allowing a single participant to unilaterally produce a valid group signature without the required quorum.

### Finding Description

`assert_sign_inputs` is the public validation gate for FROST EdDSA/RedJubjub signing. It performs the following checks: [1](#0-0) 

It checks `participants.len() < 2`, deduplication, self-presence, coordinator-presence, and `threshold.value() > participants.len()` — but **never** checks `threshold.value() < 2`.

The DKG validation function `assert_key_invariants` in `src/dkg.rs` performs the identical upper-bound check **and** the lower-bound check: [2](#0-1) 

The same omission exists in `frost::presign`, which also only checks the upper bound: [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no internal invariant enforcing a minimum of 2: [4](#0-3) 

So `ReconstructionLowerBound(1)` or `ReconstructionLowerBound(0)` are both constructible and accepted by `assert_sign_inputs` without error.

### Impact Explanation

In FROST, the threshold controls Lagrange interpolation during signature reconstruction. With `threshold = 1`, the interpolation degenerates: a single participant's nonce commitment and signature share is algebraically sufficient to reconstruct the group signature. No other participant's contribution is required. This means:

- A single participant (malicious or misconfigured) can call `assert_sign_inputs` with `threshold = 1`, receive `Ok(participants)`, proceed into the FROST signing protocol, and produce a cryptographically valid group signature without any other participant's involvement.
- The multi-party threshold guarantee — the core security property of the scheme — is completely bypassed.

This maps to the **Critical** impact: *Unauthorized creation of a valid threshold signature for attacker-chosen inputs*.

### Likelihood Explanation

`assert_sign_inputs` is a public library function. Any library caller — including a malicious coordinator orchestrating a signing session — can supply an arbitrary `threshold` value. There is no type-level or runtime barrier preventing `threshold = 1`. The DKG path enforces the lower bound, creating an inconsistency that a caller familiar with the DKG API might not notice is absent from the signing API.

### Recommendation

Add the same lower-bound check present in `assert_key_invariants` to both `assert_sign_inputs` and `frost::presign`:

```rust
// In assert_sign_inputs and frost::presign, after converting threshold:
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing guard in `assert_key_invariants`: [5](#0-4) 

### Proof of Concept

```rust
use threshold_signatures::frost::{assert_sign_inputs, presign, PresignArguments};
use threshold_signatures::participants::Participant;
use threshold_signatures::ReconstructionLowerBound;

let participants = vec![Participant::from(1u32), Participant::from(2u32)];
let me = Participant::from(1u32);
let coordinator = Participant::from(1u32);

// threshold = 1 — passes assert_sign_inputs with no error
let result = assert_sign_inputs(
    &participants,
    ReconstructionLowerBound::from(1usize), // below the required minimum of 2
    me,
    coordinator,
);
assert!(result.is_ok()); // succeeds — no lower-bound check

// Participant 1 can now proceed into FROST signing alone,
// producing a valid group signature without participant 2's involvement.
```

The call succeeds because `assert_sign_inputs` only checks `threshold.value() > participants.len()` (i.e., `1 > 2` → false, no error) and never checks `threshold.value() < 2`. [6](#0-5) [7](#0-6)

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

**File:** src/frost/mod.rs (L120-159)
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
