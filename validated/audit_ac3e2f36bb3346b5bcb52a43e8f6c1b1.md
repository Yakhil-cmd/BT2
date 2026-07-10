### Title
Missing Lower-Bound Threshold Validation in FROST Signing and Presigning — (File: `src/frost/mod.rs`)

---

### Summary

`assert_sign_inputs` and `presign` in `src/frost/mod.rs` validate that the threshold does not exceed the participant count, but omit the minimum-threshold check (`threshold >= 2`) that `assert_key_invariants` in `src/dkg.rs` correctly enforces. Because `ReconstructionLowerBound` is an unconstrained `usize` wrapper, a caller can supply `threshold = 1` (or `0`) to the FROST signing path, bypassing the only guard that ensures a meaningful quorum is required to produce a signature.

---

### Finding Description

`ReconstructionLowerBound` carries no invariant on its inner value: [1](#0-0) 

`assert_key_invariants` (used by DKG and reshare) correctly enforces a minimum of 2: [2](#0-1) 

However, `assert_sign_inputs` — the public validation entry point for FROST EdDSA and RedJubjub signing — only checks the upper bound: [3](#0-2) 

There is no corresponding `threshold < 2` guard. The same omission exists in `presign`: [4](#0-3) 

A caller (e.g., a malicious coordinator constructing signing arguments) can pass `threshold = 1` or `threshold = 0`. Both values satisfy `threshold.value() > participants.len()` being `false` for any non-empty participant list, so the check passes silently.

---

### Impact Explanation

In FROST, the threshold governs Lagrange interpolation during signing. With `threshold = 1`, only a single participant's share is interpolated at `x = 0`, returning that share's raw value rather than the actual reconstructed secret. The resulting signature scalar is cryptographically incorrect and will fail verification against the public key produced during DKG (which used `threshold >= 2`). With `threshold = 0`, Lagrange interpolation over an empty set causes an arithmetic failure.

In both cases, honest participants complete the protocol and receive an unusable output — a corrupted or unverifiable signature — with no indication that the threshold parameter was invalid. This maps to:

> **High: Corruption of sign outputs so honest parties accept unusable cryptographic outputs.**

---

### Likelihood Explanation

The entry path is direct: any caller of the public `assert_sign_inputs` or `presign` API can supply an arbitrary `ReconstructionLowerBound`. A malicious coordinator who controls the signing session parameters can trivially pass `threshold = 1`. No key material, cryptographic break, or external compromise is required. The inconsistency with `assert_key_invariants` means the omission is not a deliberate design choice.

---

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

This mirrors the existing check in `src/dkg.rs` and closes the inconsistency.

---

### Proof of Concept

1. Run DKG with `participants = [P1, P2, P3]`, `threshold = 2` — succeeds, produces valid `KeygenOutput`.
2. Call `assert_sign_inputs([P1, P2, P3], ReconstructionLowerBound(1), P1, P1)` — passes all checks (1 ≤ 3, P1 present, P1 is coordinator).
3. Proceed to FROST signing with `threshold = 1`; Lagrange interpolation uses only one share, producing a scalar that does not correspond to the group secret.
4. All honest participants accept the protocol output; the resulting signature fails `verify()` against the public key.
5. Signing is permanently broken for this session with no error surfaced at the validation boundary. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** src/frost/mod.rs (L44-88)
```rust
pub fn presign<C>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments<C>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError>
where
    C: Ciphersuite + Send,
    <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar: Send,
    <<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Element: std::marker::Send,
{
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args.keygen_out.private_share,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/frost/mod.rs (L119-159)
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
```
