### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing Allows Single-Party Signature Production — (`src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` and `presign` in `src/frost/mod.rs` validate that `threshold ≤ participants.len()` but impose **no lower bound** (`threshold ≥ 2`). The DKG entry point (`assert_key_invariants` in `src/dkg.rs`) correctly rejects `threshold < 2`, but this invariant is never re-enforced at the signing layer. A caller who passes `threshold = 1` receives no error, and the FROST protocol proceeds with a degree-0 polynomial, making a single participant's share sufficient to reconstruct the group secret and produce a valid signature.

---

### Finding Description

`ReconstructionLowerBound` is a plain `usize` wrapper with no enforced minimum: [1](#0-0) 

`assert_key_invariants` (DKG) correctly enforces `threshold ≥ 2`: [2](#0-1) 

`assert_sign_inputs` (FROST signing) only checks the upper bound and is **missing the lower-bound check**: [3](#0-2) 

`presign` (FROST presigning) has the same gap — only an upper-bound check, no `threshold ≥ 2` guard: [4](#0-3) 

By contrast, `validate_triple_inputs` (OT-based triple generation) does enforce the lower bound, so the OT-based ECDSA path is indirectly protected via the triple-threshold consistency check. The FROST path has no such backstop. [5](#0-4) 

---

### Impact Explanation

In FROST, the threshold governs the degree of the secret-sharing polynomial used during Lagrange interpolation at signing time. With `threshold = 1`, the polynomial is degree-0 (a constant), meaning **a single participant's share alone reconstructs the group secret scalar**. Any participant (including the coordinator) can therefore produce a fully valid threshold signature unilaterally, without the cooperation of any other party. This directly violates the threshold security model and constitutes unauthorized creation of a valid threshold signature.

**Impact: Critical** — Unauthorized creation of a valid threshold signature for attacker-chosen inputs.

---

### Likelihood Explanation

The threshold parameter is caller-supplied at every signing invocation. A malicious coordinator who controls the session setup can pass `threshold = 1` to their own instance and instruct other participants to do the same (e.g., by falsely claiming the DKG was performed with threshold 1). Because the library performs no cross-check between the signing threshold and the threshold embedded in `KeygenOutput`, honest participants have no library-level mechanism to detect the mismatch. A buggy integration that accidentally passes the wrong threshold value would trigger the same outcome silently.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces, directly inside `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Additionally, consider validating that the signing threshold matches the threshold stored in `KeygenOutput` (if it is persisted there) to prevent a coordinator from silently downgrading the threshold between DKG and signing.

---

### Proof of Concept

1. Run DKG with `participants = [P1, P2, P3]` and `threshold = 2` (accepted by `assert_key_invariants`).
2. Coordinator calls `assert_sign_inputs(&[P1, P2, P3], /*threshold=*/1, P1, P1)`.
   - `participants.len() < 2` → false (3 participants).
   - `threshold.value() > participants.len()` → false (1 ≤ 3).
   - No lower-bound check → **returns `Ok`**.
3. Coordinator calls `presign` with `threshold = 1` → accepted.
4. Coordinator calls the EdDSA sign function with `threshold = 1`; Lagrange interpolation over a degree-0 polynomial requires only P1's share.
5. P1 alone produces a cryptographically valid FROST signature, without P2 or P3 participating. [6](#0-5)

### Citations

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

**File:** src/dkg.rs (L579-582)
```rust
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```
