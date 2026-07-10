### Title
Missing Lower-Bound Threshold Validation in FROST Signing Allows Single-Party Signature Production - (File: src/frost/mod.rs)

### Summary

The `assert_sign_inputs` function in `src/frost/mod.rs` validates that the threshold does not exceed the participant count (upper bound) but omits the lower-bound check (`threshold >= 2`) that is enforced in `assert_key_invariants` in `src/dkg.rs`. A malicious coordinator can invoke the FROST signing entry points with `threshold = 1`, bypassing the multi-party quorum requirement and producing a valid threshold signature unilaterally with a single share.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold parameter:

```rust
// src/dkg.rs lines 573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
```

`assert_sign_inputs` in `src/frost/mod.rs` only enforces the upper bound:

```rust
// src/frost/mod.rs lines 144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold = 1 or 0 passes silently
```

The same omission exists in the `presign` function in `src/frost/mod.rs` (lines 71–77), which also only checks the upper bound.

`ReconstructionLowerBound` is a plain `usize` newtype with no enforced minimum:

```rust
// src/thresholds.rs lines 9-12
pub struct ReconstructionLowerBound(usize);
```

**Exploit path:** A malicious coordinator constructs a call to the FROST EdDSA or RedJubjub signing entry point (which internally calls `assert_sign_inputs`) with `threshold = 1` and a participant list of size ≥ 2. Validation passes. The signing protocol then requires only 1 signature share to reconstruct the final signature. The coordinator, holding their own share, produces a valid FROST signature over an attacker-chosen message without cooperation from any other participant.

### Impact Explanation

With `threshold = 1` accepted by `assert_sign_inputs`, the FROST signing protocol's quorum requirement is reduced to a single party. Any participant acting as coordinator can unilaterally produce a cryptographically valid threshold signature over an arbitrary message, bypassing the multi-party security guarantee that the DKG established with `threshold >= 2`. This maps directly to the Critical impact category: **unauthorized creation of a valid threshold signature for attacker-chosen inputs**.

### Likelihood Explanation

The coordinator role is a documented trust boundary in this library. A malicious coordinator is an explicitly considered threat model (see `RESEARCHER.md`). The entry point is reachable by any caller who controls the `threshold` argument passed to the FROST signing functions. No special privileges beyond being a protocol participant are required. The missing check is a single missing `if threshold < 2` guard, making this a straightforward misconfiguration or deliberate exploitation path.

### Recommendation

Add the same lower-bound check present in `assert_key_invariants` to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Additionally, consider enforcing the minimum at the type level in `ReconstructionLowerBound` (e.g., a constructor that rejects values below 2) so that the invariant cannot be violated by any future call site.

### Proof of Concept

1. Run DKG with participants `[P1, P2, P3]` and `threshold = 2` (enforced by `assert_key_invariants`). Each party receives a valid key share.
2. Call the FROST EdDSA or RedJubjub `sign` entry point as coordinator `P1` with `participants = [P1, P2]` and `threshold = 1`.
3. `assert_sign_inputs` checks: `1 > 2`? No → passes. `1 < 2`? **Not checked** → passes.
4. The signing protocol proceeds requiring only 1 share. `P1` contributes their own share and the protocol completes, producing a valid signature over the chosen message without `P2`'s participation.
5. The resulting signature verifies correctly against the public key established during DKG, constituting an unauthorized threshold signature. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** src/dkg.rs (L579-582)
```rust
    // Step 1.1
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
    }
```

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```
