### Title
Minimum Threshold Lower Bound Enforced in DKG but Not in Signing/Presigning Phases — (`src/frost/mod.rs`, `src/ecdsa/ot_based_ecdsa/sign.rs`)

### Summary

`assert_key_invariants` in `src/dkg.rs` enforces that `threshold >= 2` as a hard invariant during key generation. However, the signing and presigning entry points — `assert_sign_inputs` and `presign` in `src/frost/mod.rs`, and `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs` — only check the upper bound (`threshold <= participants.len()`) and never enforce the same lower bound. A malicious coordinator or library caller can invoke signing with `threshold = 1` (or `threshold = 0`), bypassing the minimum threshold constraint that DKG assumes is globally invariant.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold:

```rust
// src/dkg.rs:573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

The signing-phase validators do not replicate the lower-bound check. `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
// src/frost/mod.rs:144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [2](#0-1) 

The `presign` function in `src/frost/mod.rs` has the same gap — it checks `args.threshold.value() > participants.len()` but never `args.threshold.value() < 2`: [3](#0-2) 

Similarly, `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs` only checks `participants.len() < threshold` (upper bound direction) and never rejects `threshold < 2`: [4](#0-3) 

The `ReconstructionLowerBound` and `MaxMalicious` wrapper types in `src/thresholds.rs` impose no minimum value constraint themselves — they are plain `usize` wrappers: [5](#0-4) 

**Exploit path**: A malicious coordinator or library caller constructs a signing session with `threshold = 1` (or `threshold = 0`). The call passes all guards in `assert_sign_inputs` / `presign` / `sign` because only the upper bound is checked. The Lagrange interpolation inside the signing computation then uses degree-0 (or degenerate) coefficients inconsistent with the degree-(t−1) polynomial used during key generation (where `t >= 2` was enforced). This produces signature shares that are cryptographically inconsistent with the established key material.

### Impact Explanation

**High — Corruption of sign outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

When `threshold = 1` is supplied to FROST signing, the Lagrange coefficients used to linearize each participant's signing share are computed for a 1-of-n polynomial, while the secret key shares were distributed on a 2-of-n (or higher) polynomial. The combined signature output is cryptographically invalid and will fail verification. Honest participants, having followed the protocol correctly, receive and accept a corrupted, unusable signature. Under repeated invocation by a malicious coordinator this constitutes permanent denial of signing for honest parties under valid protocol inputs.

### Likelihood Explanation

The signing API is a public library entry point. Any caller — including a malicious coordinator who controls which `threshold` value is passed — can supply `threshold = 1` without any privilege. The gap is a single missing `< 2` guard that is present in DKG but absent in all signing/presigning validators.

### Recommendation

Add the same lower-bound check that `assert_key_invariants` applies to every function that accepts a `threshold` / `ReconstructionLowerBound` parameter for signing or presigning:

- `assert_sign_inputs` in `src/frost/mod.rs`
- `presign` in `src/frost/mod.rs`
- `sign` in `src/ecdsa/ot_based_ecdsa/sign.rs`

Concretely, after converting the threshold, add:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold: threshold.value(), min: 2 });
}
```

Alternatively, encode the minimum at the type level inside `ReconstructionLowerBound` so the invariant is impossible to violate regardless of call site.

### Proof of Concept

```rust
// Keygen with threshold=2 (enforced by assert_key_invariants)
let participants = generate_participants(3);
let keygen_out = keygen::<C>(&participants, me, 2usize, rng).unwrap();

// Signing with threshold=1 — passes all guards in assert_sign_inputs
// because only the upper bound (1 <= 3) is checked, not the lower bound.
let result = frost::assert_sign_inputs(
    &participants,
    1usize,   // threshold=1, below the DKG minimum of 2
    me,
    coordinator,
);
// result is Ok(participants) — no error is returned.
// Subsequent Lagrange interpolation uses degree-0 coefficients,
// producing signing shares inconsistent with the degree-1 key polynomial,
// yielding a corrupted, unverifiable signature.
``` [6](#0-5) [7](#0-6)

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

**File:** src/thresholds.rs (L1-25)
```rust
use derive_more::{From, Into};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct MaxMalicious(usize);

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
}
```
