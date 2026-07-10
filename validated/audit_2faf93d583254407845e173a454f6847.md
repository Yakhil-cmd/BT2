### Title
Missing Minimum Threshold Lower-Bound Check in FROST Presign and Sign Validation — (`File: src/frost/mod.rs`)

### Summary
The FROST presign and sign input-validation functions accept a `threshold` value of 1 (or 0) without error, while the DKG layer explicitly rejects any threshold below 2. A caller who passes `threshold = 1` to `presign()` or `assert_sign_inputs()` receives no error, the protocol runs to completion, and the resulting presignature or aggregated signature is cryptographically inconsistent with the key material produced by DKG, causing honest parties to obtain unusable outputs.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces a strict lower bound:

```rust
// src/dkg.rs lines 580-582
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

The FROST `presign()` function in `src/frost/mod.rs` validates only the upper bound:

```rust
// src/frost/mod.rs lines 71-77
// validate threshold
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
``` [2](#0-1) 

There is no corresponding `threshold < 2` guard. The same omission exists in `assert_sign_inputs()`:

```rust
// src/frost/mod.rs lines 144-150
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no lower-bound check
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no internal validation, so any value including 0 or 1 is accepted without restriction:

```rust
// src/thresholds.rs lines 9-12
pub struct ReconstructionLowerBound(usize);
``` [4](#0-3) 

### Impact Explanation

In FROST, the threshold governs the degree of the secret-sharing polynomial used during DKG and the Lagrange interpolation performed during signing. DKG always produces shares for a polynomial of degree `threshold − 1 ≥ 1`. If a caller later invokes `presign` or `assert_sign_inputs` with `threshold = 1`, the signing layer computes Lagrange coefficients for a degree-0 polynomial (constant), which is inconsistent with the degree-1 polynomial used during key generation. The aggregated signature scalar is computed from the wrong linear combination of shares, producing a signature that fails standard FROST verification against the master public key. Honest parties who accept and attempt to use this output receive a permanently unusable cryptographic result.

**Allowed impact matched:** High — Corruption of presign/sign outputs so honest parties accept inconsistent or unusable cryptographic outputs.

### Likelihood Explanation

Any library caller who constructs a `PresignArguments` with `threshold: ReconstructionLowerBound(1)` or calls `assert_sign_inputs` with threshold 1 triggers this path. No special privilege is required. The inconsistency between DKG validation (which rejects threshold < 2) and FROST sign validation (which does not) makes accidental misconfiguration realistic, especially when a caller migrates from one scheme to another or writes a wrapper that does not re-read the DKG threshold from the stored `KeygenOutput`.

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` applies to every FROST threshold validation site:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be added in both `presign()` (after the `participants.len() < 2` check) and `assert_sign_inputs()` (after the `participants.len() < 2` check), mirroring the existing pattern in `assert_key_invariants`. [5](#0-4) [6](#0-5) 

### Proof of Concept

1. Run DKG with `participants = [P1, P2, P3]`, `threshold = 2`. This succeeds and produces valid shares for a degree-1 polynomial.
2. Call `presign(participants, me, PresignArguments { threshold: ReconstructionLowerBound(1), keygen_out: ... }, rng)`. The function passes all validation checks and returns a `Protocol` without error.
3. Call `assert_sign_inputs(participants, ReconstructionLowerBound(1), me, coordinator)`. Again, no error is returned.
4. Proceed through the FROST signing round. The coordinator aggregates shares using Lagrange coefficients computed for a degree-0 polynomial (threshold=1), producing a scalar `z` that does not correspond to the actual secret key.
5. The resulting signature fails verification against the master public key, delivering a permanently unusable output to all honest parties — with no error surfaced by the library. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** src/thresholds.rs (L9-12)
```rust
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into,
)]
pub struct ReconstructionLowerBound(usize);
```
