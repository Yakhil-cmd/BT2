### Title
Missing Lower-Bound Threshold Validation in FROST Signing Allows Threshold=0 or Threshold=1 to Corrupt Sign Outputs - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` validate that the threshold does not exceed the participant count, but omit the lower-bound check (`threshold < 2`) that is consistently enforced in `assert_key_invariants` (`src/dkg.rs`) and `validate_triple_inputs` (`src/ecdsa/ot_based_ecdsa/triples/generation.rs`). A caller supplying `threshold = 0` or `threshold = 1` bypasses this guard, causing the FROST signing protocol to proceed with a cryptographically invalid threshold and produce an unusable signature that honest parties accept as protocol output.

### Finding Description
`assert_key_invariants` in `src/dkg.rs` enforces two threshold bounds:

```
if threshold > participants.len() { ... ThresholdTooLarge }
if threshold < 2                  { ... ThresholdTooSmall }
```

`validate_triple_inputs` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` applies the same two-sided check. [1](#0-0) 

By contrast, `assert_sign_inputs` in `src/frost/mod.rs` only checks the upper bound:

```rust
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no ThresholdTooSmall check
``` [2](#0-1) 

The `presign` function in the same file has the identical gap:

```rust
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no ThresholdTooSmall check
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforced at construction time, so `ReconstructionLowerBound(0)` and `ReconstructionLowerBound(1)` are both valid values that pass the existing guard. [4](#0-3) 

### Impact Explanation
**High — Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

- **threshold = 1**: FROST Lagrange interpolation assigns coefficient 1 to the single selected signer. The combined signature share equals that one participant's raw share contribution, not the correct reconstruction of the distributed secret. The resulting `(R, z)` pair fails verification against the public key produced by DKG (which enforced threshold ≥ 2). All honest participants complete the protocol and accept this invalid signature as the final output.
- **threshold = 0**: Lagrange interpolation over an empty signer set is undefined; depending on the underlying `frost-core` implementation this can panic at runtime, permanently aborting the signing session for all honest parties.

In both cases honest parties cannot distinguish a legitimately failed signing from a corrupted one, and the signing session is unrecoverable.

### Likelihood Explanation
**Low-to-Medium.** The threshold is a caller-supplied parameter with no type-level enforcement. Any participant or coordinator that invokes the EdDSA or RedJubjub signing entry points (which call `assert_sign_inputs`) can pass `threshold = 1` or `threshold = 0`. No special privilege is required beyond being a protocol participant. The attack is trivially reproducible by any library consumer who either makes an honest mistake or acts maliciously.

### Recommendation
Add the same lower-bound check that `assert_key_invariants` and `validate_triple_inputs` already apply:

```rust
// In assert_sign_inputs and presign (src/frost/mod.rs)
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing pattern in `src/dkg.rs` and `src/ecdsa/ot_based_ecdsa/triples/generation.rs` and closes the inconsistency. [5](#0-4) 

### Proof of Concept
1. Call `assert_sign_inputs(participants, 1usize, me, coordinator)` with a valid 2-participant list.
2. The check `threshold.value() > participants.len()` evaluates `1 > 2 = false` — no error is returned.
3. The signing protocol proceeds with `threshold = 1`.
4. FROST Lagrange interpolation uses a single signer's share with coefficient 1, producing a signature that does not verify against the DKG public key.
5. All honest parties accept this invalid signature as the protocol result.

Compare: calling `keygen(participants, me, 1usize, rng)` correctly returns `InitializationError::ThresholdTooSmall { threshold: 1, min: 2 }` because `assert_key_invariants` has the lower-bound guard. [6](#0-5)  The signing path has no equivalent protection. [7](#0-6)

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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```
