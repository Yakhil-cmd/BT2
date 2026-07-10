### Title
Missing Lower-Bound Threshold Check in `assert_sign_inputs` Allows Sub-Quorum FROST Signing - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` function in `src/frost/mod.rs` validates the signing threshold for FROST (EdDSA / RedJubjub) protocols but only enforces an upper bound (`threshold <= participants.len()`). It is missing the lower-bound check (`threshold >= 2`) that is present in the analogous DKG validation function `assert_key_invariants` in `src/dkg.rs`. A malicious coordinator or library caller can supply `threshold = 1`, reducing the effective signing quorum to a single participant and enabling unauthorized production of a valid threshold signature.

### Finding Description
`assert_sign_inputs` in `src/frost/mod.rs` performs the following checks:

```
participants.len() >= 2
no duplicate participants
me ∈ participants
threshold <= participants.len()   ← upper bound only
coordinator ∈ participants
``` [1](#0-0) 

The lower-bound guard `threshold >= 2` is entirely absent. The directly analogous function `assert_key_invariants` in `src/dkg.rs` explicitly includes this check:

```rust
// Step 1.1
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [2](#0-1) 

The `ThresholdTooSmall` error variant exists in the error enum and is used in DKG and triple-generation paths, but is never emitted from the FROST signing path. [3](#0-2) 

`assert_sign_inputs` is the sole validation gate called by both `src/frost/eddsa/sign.rs` and `src/frost/redjubjub/sign.rs` before the signing state machine is started. The `presign` function in the same file has the identical omission: [4](#0-3) 

Because `ReconstructionLowerBound` does not self-enforce a minimum of 2 (the DKG path must check it explicitly after conversion to `usize`), passing `threshold = 1` is a valid call that clears all guards in `assert_sign_inputs`.

### Impact Explanation
In FROST, the threshold controls Lagrange interpolation during partial-signature aggregation. With `threshold = 1`, only one participant's partial signature is required for a valid aggregate. A malicious coordinator who controls the signing session can:

1. Invoke the signing protocol with `threshold = 1` and a participant list of ≥ 2 honest parties.
2. Collect only their own partial signature (or that of one colluding party).
3. Aggregate it with Lagrange coefficient 1 (trivial single-point interpolation) to obtain a fully valid group signature over an attacker-chosen message.

This satisfies the **Critical** impact: *Unauthorized creation of a valid threshold signature for attacker-chosen inputs*.

### Likelihood Explanation
The threshold value is supplied directly by the library caller at signing time and is not bound to the threshold used during key generation. Any participant acting as coordinator, or any application layer that constructs the signing call, can freely set `threshold = 1`. No cryptographic capability or key compromise is required — only the ability to call the public API with an integer argument.

### Recommendation
Add the missing lower-bound guard to `assert_sign_inputs` (and to the `presign` function) in `src/frost/mod.rs`, mirroring the check already present in `assert_key_invariants`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted immediately after the upper-bound check at line 145, consistent with the ordering in `assert_key_invariants`. [5](#0-4) 

### Proof of Concept
```
// Attacker-controlled call
let participants = vec![alice, bob, carol];   // 3 honest parties
let result = assert_sign_inputs(
    &participants,
    1u16,          // threshold = 1 — passes all current guards
    alice,
    alice,
);
assert!(result.is_ok());   // succeeds today; should return ThresholdTooSmall

// Attacker then drives the FROST sign protocol with threshold=1,
// contributes only their own partial signature, and obtains a
// valid group signature without bob or carol's participation.
``` [1](#0-0) [6](#0-5)

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

**File:** src/errors.rs (L140-141)
```rust
    #[error("threshold {threshold} is too small, it must be at least {min}")]
    ThresholdTooSmall { threshold: usize, min: usize },
```
