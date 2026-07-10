### Title
Missing Minimum Threshold Validation in `assert_sign_inputs` Allows Signing with Threshold=1 — (`File: src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` in `src/frost/mod.rs` is missing the `threshold < 2` lower-bound check that is present in the parallel keygen validation function `assert_key_invariants` in `src/dkg.rs`. Because `ReconstructionLowerBound` is an unconstrained `usize` wrapper, any caller can pass `threshold = 1` to `sign_v1`, `sign_v2` (EdDSA), or `sign` (RedJubjub), bypassing the minimum threshold requirement entirely. The `ThresholdTooSmall` error can never be triggered from the FROST signing path. This causes the signing protocol to proceed with incorrect Lagrange interpolation, producing an unusable/invalid signature and permanently denying honest parties the ability to sign.

---

### Finding Description

`assert_key_invariants` enforces two threshold bounds:

```rust
// src/dkg.rs lines 573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs`, which gates all FROST signing entry points, only enforces the upper bound:

```rust
// src/frost/mod.rs lines 144-150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check for threshold < 2
``` [2](#0-1) 

`ReconstructionLowerBound` is a plain `usize` newtype with no minimum enforced at construction: [3](#0-2) 

So `ReconstructionLowerBound(1)` is a valid value that passes all type-level checks. `assert_sign_inputs` accepts it without error as long as `participants.len() >= 2`.

All three FROST signing entry points delegate to `assert_sign_inputs`:

- `sign_v1` and `sign_v2` in `src/frost/eddsa/sign.rs`
- `sign` in `src/frost/redjubjub/sign.rs` [4](#0-3) [5](#0-4) 

Once `assert_sign_inputs` returns `Ok`, the validated `threshold` value flows directly into `construct_key_package(threshold, ...)` inside `do_sign_coordinator_v1` and `do_sign_coordinator_v2`: [6](#0-5) 

The `frost_ed25519` library uses this threshold to build the `KeyPackage` and compute Lagrange coefficients during `round2::sign` and `aggregate`. With `threshold = 1`, the interpolation uses a single point with coefficient 1, which does not reconstruct the actual secret key (which was generated over a degree-`t-1` polynomial with `t >= 2`). The resulting signature fails verification.

---

### Impact Explanation

A caller who passes `threshold = 1` to any FROST signing function causes the signing session to produce a cryptographically invalid signature — one that fails `aggregate`'s internal verification or produces a value that does not verify against the public key. Honest participants who follow the protocol correctly cannot produce a valid signature under these conditions. If a malicious coordinator or library integrator consistently supplies `threshold = 1`, signing is permanently denied for all honest parties.

This maps to: **High — Corruption of sign outputs so honest parties produce unusable cryptographic outputs; and/or Permanent denial of signing for honest parties under valid protocol inputs.**

---

### Likelihood Explanation

The `ReconstructionLowerBound` type accepts any `usize`, including 1. The signing API is a public library function. Any integrator, malicious participant controlling the signing invocation, or malicious coordinator can supply `threshold = 1`. No special privilege or cryptographic capability is required — only the ability to call the public signing API with an attacker-chosen parameter.

---

### Recommendation

Add the same lower-bound check to `assert_sign_inputs` that exists in `assert_key_invariants`:

```rust
// src/frost/mod.rs — inside assert_sign_inputs, after the upper-bound check
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing pattern in `assert_key_invariants` and ensures the `ThresholdTooSmall` error is reachable from the FROST signing path.

---

### Proof of Concept

1. Generate a keygen output with `threshold = 2` and `participants = [P1, P2]` using the normal DKG flow.
2. Call `sign_v1` with the same participants but `threshold = 1`:
   ```rust
   sign_v1(
       &[P1, P2],
       ReconstructionLowerBound(1),  // bypasses assert_sign_inputs — no ThresholdTooSmall error
       me,
       coordinator,
       keygen_output,
       message,
       rng,
   )
   ```
3. `assert_sign_inputs` accepts `threshold = 1` because only the upper-bound check (`1 > 2` → false) is present.
4. The protocol proceeds; `construct_key_package(ReconstructionLowerBound(1), ...)` is called.
5. `round2::sign` and `aggregate` use Lagrange interpolation with a single point (coefficient = 1), producing a signature that does not correspond to the actual secret key.
6. The signature fails verification — honest parties cannot produce a valid output. [7](#0-6) [8](#0-7)

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

**File:** src/frost/eddsa/sign.rs (L46-47)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```

**File:** src/frost/eddsa/sign.rs (L143-146)
```rust
    let key_package = construct_key_package(threshold, me, signing_share, &vk_package)?;
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
```

**File:** src/frost/redjubjub/sign.rs (L49-50)
```rust
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;
```
