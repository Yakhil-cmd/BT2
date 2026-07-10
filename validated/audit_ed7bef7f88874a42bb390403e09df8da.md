### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Initialization — (`src/frost/mod.rs`)

### Summary
`assert_sign_inputs` and `presign` in `src/frost/mod.rs` validate that `threshold` does not exceed the participant count but omit the lower-bound check (`threshold >= 2`) that is explicitly enforced in the DKG path. A caller supplying `threshold = 1` (or `0`) passes all initialization guards and enters the FROST signing protocol with a degenerate threshold, producing an unusable or cryptographically incorrect signature output.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on `threshold`:

```
// upper bound
if threshold > participants.len() { ... ThresholdTooLarge }
// lower bound  ← present in DKG
if threshold < 2 { ... ThresholdTooSmall { threshold, min: 2 } }
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs` enforces only the upper bound:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← NO lower-bound check; threshold = 1 or 0 passes silently
``` [2](#0-1) 

The same omission exists in `presign` in the same file:

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no threshold < 2 guard
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforcement of its own, so any value including `0` or `1` is accepted at the type level. [4](#0-3) 

### Impact Explanation

In FROST, the threshold controls how many signature shares are Lagrange-interpolated to reconstruct the group signing key contribution. With `threshold = 1`, only one participant's share is used and its Lagrange coefficient collapses to `1`, so the aggregated signing key becomes that participant's individual share `s_i` rather than the group secret `s`. The resulting signature is computed under `s_i · G`, not the group public key `s · G`. Honest parties either receive an invalid/unusable signature as the protocol output, or the `frost_core` aggregation step returns `ErrorFrostAggregation` / `ErrorFrostSigningFailed`, permanently denying signing for that session.

This maps to: **High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs**, or **High — Permanent denial of signing for honest parties under valid protocol inputs**.

### Likelihood Explanation

`assert_sign_inputs` is a public library function. Any caller — including a malicious coordinator constructing `PresignArguments` with `threshold: ReconstructionLowerBound(1)` — can reach this path directly. No special privilege is required; the type system places no lower-bound constraint on `ReconstructionLowerBound`. [5](#0-4) 

### Recommendation

Add the same lower-bound guard present in `assert_key_invariants` to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Optionally, enforce the invariant at construction time inside `ReconstructionLowerBound::new` so the constraint cannot be bypassed by any future call site. [4](#0-3) 

### Proof of Concept

```rust
use threshold_signatures::frost::assert_sign_inputs;
use threshold_signatures::participants::Participant;
use threshold_signatures::ReconstructionLowerBound;

let p0 = Participant::from(1u32);
let p1 = Participant::from(2u32);
let participants = vec![p0, p1];

// threshold = 1 passes all current guards in assert_sign_inputs
let result = assert_sign_inputs(
    &participants,
    ReconstructionLowerBound::from(1usize), // degenerate threshold
    p0,
    p0,
);
// result is Ok(_) — no error returned
// Subsequent FROST signing with this threshold produces a signature
// under p0's individual share, not the group key, yielding an
// invalid/unusable output or an aggregation error.
assert!(result.is_ok()); // demonstrates missing validation
``` [6](#0-5) [7](#0-6)

### Citations

**File:** src/dkg.rs (L572-582)
```rust
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
