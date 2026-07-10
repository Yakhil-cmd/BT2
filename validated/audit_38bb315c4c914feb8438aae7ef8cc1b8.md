### Title
Missing Lower-Bound Validation on `threshold` in FROST Signing/Presigning Allows Corrupted Signature Outputs - (File: src/frost/mod.rs)

### Summary
The `assert_sign_inputs` and `presign` functions in `src/frost/mod.rs` validate that `threshold` is not too large but omit the lower-bound check (`threshold >= 2`) that is explicitly enforced in `assert_key_invariants` in `src/dkg.rs`. A caller can pass `threshold = 1` to the FROST signing or presigning entry points; the validation passes, the protocol executes with incorrect Lagrange coefficients, and the resulting signature is cryptographically invalid and will not verify against the public key that was generated under `threshold >= 2`.

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

`assert_sign_inputs` in `src/frost/mod.rs`, which is the validation gate for FROST EdDSA and RedJubjub signing, only checks the upper bound:

```rust
// src/frost/mod.rs:144-150
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check; threshold = 1 passes silently
``` [2](#0-1) 

The `presign` function in the same file has the identical gap:

```rust
// src/frost/mod.rs:72-77
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` wrapper with no invariant enforced at construction time, so `threshold = 1` (or even `0`) is a valid value at the type level: [4](#0-3) 

### Impact Explanation

In FROST, the signing threshold governs Lagrange interpolation of signature shares. The key was generated under `threshold >= 2` (enforced by DKG), meaning the secret polynomial has degree `>= 1`. When signing is invoked with `threshold = 1`, only one participant's share is collected and the Lagrange coefficient degenerates to `1` (trivial single-point interpolation). The reconstructed signature scalar is then just the single raw share, which does not equal the correct reconstruction of the distributed secret. The resulting signature fails verification against the public key. Every honest participant that accepted and forwarded this output has accepted a cryptographically inconsistent signing result.

This maps to: **High — Corruption of sign outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

### Likelihood Explanation

The entry points `presign` and `assert_sign_inputs` are public library API. Any caller that constructs a `PresignArguments` or calls the signing helpers with a `ReconstructionLowerBound` of `1` (e.g., by accident, misconfiguration, or a malicious coordinator supplying parameters) will silently bypass the guard. The DKG phase correctly rejects `threshold = 1`, creating a false sense of security that the threshold is always validated. The inconsistency between the two validation functions makes accidental misuse likely.

### Recommendation

Add the same lower-bound check that `assert_key_invariants` already performs to both `assert_sign_inputs` and `presign` in `src/frost/mod.rs`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

Apply the same fix to any other signing/presigning entry points that accept a `ReconstructionLowerBound` without delegating to `assert_key_invariants`. In the long term, consider encoding the `>= 2` invariant directly into the `ReconstructionLowerBound` type so it cannot be constructed with an invalid value.

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 2` (succeeds, enforced by `assert_key_invariants`).
2. Call `frost::presign` with the resulting `KeygenOutput` but supply `threshold = 1` inside `PresignArguments`. The call returns `Ok(...)` because `assert_sign_inputs` / `presign` only check the upper bound.
3. Proceed to the signing phase using the presignature and `threshold = 1`. The coordinator collects only one signature share, applies Lagrange coefficient `1`, and assembles a scalar that is not the correct reconstruction of the distributed secret.
4. Verify the resulting signature against the public key — verification fails, confirming the output is corrupted. [5](#0-4) [6](#0-5) [7](#0-6)

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
