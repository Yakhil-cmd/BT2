### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing and Presigning Allows Threshold-1 Protocol Execution — (`src/frost/mod.rs`)

---

### Summary

The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` validate only the upper bound of the `threshold` parameter (`threshold <= participants.len()`) but omit the lower-bound check (`threshold >= 2`) that is consistently enforced in `assert_key_invariants` (`src/dkg.rs`). Because `ReconstructionLowerBound` is a plain `usize` wrapper with no intrinsic minimum, a malicious coordinator or library caller can supply `threshold = 1` (or `0`), bypassing the security invariant that at least two shares are required to reconstruct a secret. This causes the FROST signing protocol to execute with a degree-0 Lagrange interpolation, producing a cryptographically incorrect signature and denying signing for honest participants.

---

### Finding Description

**Root cause — inconsistent lower-bound enforcement:**

`assert_key_invariants` in `src/dkg.rs` correctly enforces a minimum threshold of 2:

```rust
// src/dkg.rs line 580
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound and has **no lower-bound guard**:

```rust
// src/frost/mod.rs lines 144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: threshold.value(),
        max: participants.len(),
    });
}
``` [2](#0-1) 

The same omission exists in `presign` in `src/frost/mod.rs`:

```rust
// src/frost/mod.rs lines 71-77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge {
        threshold: args.threshold.into(),
        max: participants.len(),
    });
}
``` [3](#0-2) 

**Type has no intrinsic minimum:**

`ReconstructionLowerBound` is a transparent `usize` newtype with no constructor-level minimum enforcement:

```rust
pub struct ReconstructionLowerBound(usize);
``` [4](#0-3) 

Any `usize` value — including `0` or `1` — converts into a valid `ReconstructionLowerBound` via the derived `From` impl, and passes both validation functions without error.

**Contrast with DKG:** `assert_key_invariants` is the only entry-point that enforces `threshold >= 2`. All FROST signing and presigning entry-points skip this check entirely. [5](#0-4) 

---

### Impact Explanation

In FROST (and Shamir-based threshold schemes generally), the threshold `t` determines the degree of the secret-sharing polynomial (`t-1`) and the minimum number of Lagrange basis points required to interpolate the secret. When `threshold = 1` is supplied at signing time:

- The Lagrange interpolation degenerates to a single-point evaluation (degree-0 polynomial).
- Each participant's signature share is multiplied by a Lagrange coefficient computed over only one identifier, yielding a value that does not correspond to the actual secret share polynomial evaluated at zero.
- The aggregated signature is cryptographically invalid relative to the public key produced during DKG (which used `threshold = 2`).
- Honest participants who verify the final signature will reject it, and the signing session produces an unusable output.

This maps to the allowed High impact: **Corruption of sign outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

---

### Likelihood Explanation

The coordinator role in FROST controls the signing session initialization, including the `threshold` and `participants` arguments passed to `assert_sign_inputs` and `presign`. A malicious or compromised coordinator can trivially supply `threshold = 1` — the value passes all existing validation checks (it is not greater than `participants.len()`, and `participants.len() >= 2` is satisfied independently). No cryptographic capability or key material is required to trigger this path; it is a pure parameter-manipulation attack reachable by any party that initiates a signing session.

---

### Recommendation

Add the same lower-bound guard present in `assert_key_invariants` to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```diff
// assert_sign_inputs
+ if threshold.value() < 2 {
+     return Err(InitializationError::ThresholdTooSmall {
+         threshold: threshold.value(),
+         min: 2,
+     });
+ }
  if threshold.value() > participants.len() { ... }

// presign
+ if args.threshold.value() < 2 {
+     return Err(InitializationError::ThresholdTooSmall {
+         threshold: args.threshold.into(),
+         min: 2,
+     });
+ }
  if args.threshold.value() > participants.len() { ... }
```

Consider also enforcing the minimum at the `ReconstructionLowerBound` construction site (e.g., a `new(v: usize) -> Result<Self, _>` constructor) so the invariant is type-level rather than call-site-level.

---

### Proof of Concept

1. Complete a FROST DKG with 3 participants and `threshold = 2`. All participants receive valid key shares for a degree-1 polynomial.
2. A malicious coordinator calls `assert_sign_inputs(&participants, 1usize, me, coordinator)`. The call returns `Ok(participant_list)` — no error is raised because `1 <= 3` and `participants.len() >= 2`.
3. The coordinator calls `presign` with `args.threshold = ReconstructionLowerBound::from(1usize)`. Again, no error.
4. The coordinator drives the FROST signing protocol with `threshold = 1`. The Lagrange coefficient for each participant is computed over a single-element set, yielding coefficient `1` for that participant and `0` for all others — a degenerate interpolation inconsistent with the degree-1 shares produced during DKG.
5. The aggregated signature `z = Σ z_i` is computed from incorrectly weighted shares and fails verification against the public key. Honest parties receive an unusable, invalid signature, and the signing session is corrupted.

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

**File:** src/frost/mod.rs (L144-150)
```rust
    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }
```

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```
