### Title
Missing Lower-Bound Threshold Validation in FROST Presign and Sign Allows Threshold-1 Signing — (`File: src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` and `presign` in `src/frost/mod.rs` validate that `threshold ≤ participants.len()` (upper bound) but **never check that `threshold ≥ 2`** (lower bound). The DKG path enforces both bounds in `assert_key_invariants`. The missing lower-bound check is the direct analog of the reported pattern: individual values are checked against one limit while the complementary limit is silently omitted, allowing an out-of-range value to propagate into the protocol.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces two threshold constraints:

```rust
if threshold > participants.len() { /* ThresholdTooLarge */ }
if threshold < 2               { /* ThresholdTooSmall  */ }
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs`, which gates both `sign_v1` and `sign_v2` for EdDSA/RedJubjub, enforces **only** the upper bound:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { … });
}
// ← no lower-bound check; threshold = 1 is silently accepted
``` [2](#0-1) 

The same omission exists in the FROST `presign` entry-point:

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { … });
}
// ← no lower-bound check
``` [3](#0-2) 

`sign_v2` (and by alias `sign_v1`) delegates all validation to `assert_sign_inputs`:

```rust
pub fn sign_v2(…, threshold: impl Into<ReconstructionLowerBound> + Copy, …) {
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
``` [4](#0-3) 

Because `ReconstructionLowerBound` is a plain newtype over `usize` with no built-in minimum, passing `threshold = 1` clears every guard in the signing and presigning paths.

---

### Impact Explanation

With `threshold = 1`, FROST Lagrange interpolation at zero requires only **one** participant's signature share to reconstruct the aggregate signature. A single participant therefore produces a cryptographically valid threshold signature over any message of their choice, without cooperation from any other party. This directly violates the core security guarantee of threshold signing: that no strict subset of size less than the threshold can forge a signature.

This maps to the allowed Critical impact: **Unauthorized creation of a valid threshold signature for attacker-chosen inputs.**

---

### Likelihood Explanation

The library is a caller-facing API. Any application that:
- allows a coordinator or participant to supply the `threshold` argument at runtime, or
- has a bug or misconfiguration that passes `1` as the threshold,

will silently proceed through all validation and execute the full FROST signing protocol with a broken threshold. The missing check is invisible to callers because the error type `ThresholdTooSmall` exists and is used elsewhere, creating a false sense of completeness.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces, in both `assert_sign_inputs` and `presign`:

```rust
// in assert_sign_inputs and presign (src/frost/mod.rs)
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
``` [5](#0-4) 

Mirror the pattern already present in `assert_key_invariants`: [6](#0-5) 

---

### Proof of Concept

1. Call `presign` with `threshold = 1` and any two participants — validation passes.
2. Call `sign_v2` (or `sign_v1`) with `threshold = 1` — `assert_sign_inputs` passes.
3. Inside the FROST signing round, the single participant's share is interpolated at zero with Lagrange coefficient `1`, producing a complete, valid aggregate signature.
4. No other participant's share or cooperation is required; the threshold guarantee is entirely bypassed.

The `ThresholdTooSmall` error variant already exists in `src/errors.rs` and is used by `assert_key_invariants`, confirming the library authors intended this check — it was simply omitted from the signing path. [7](#0-6)

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

**File:** src/frost/eddsa/sign.rs (L64-73)
```rust
pub fn sign_v2(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound> + Copy,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** src/errors.rs (L140-141)
```rust
    #[error("threshold {threshold} is too small, it must be at least {min}")]
    ThresholdTooSmall { threshold: usize, min: usize },
```
