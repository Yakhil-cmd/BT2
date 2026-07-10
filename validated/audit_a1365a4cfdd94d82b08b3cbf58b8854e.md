### Title
Missing `threshold >= 2` Lower-Bound Enforcement in FROST Signing Validation — (`src/frost/mod.rs`)

### Summary

`assert_key_invariants` (DKG) enforces `threshold >= 2` as a hard lower bound, but the analogous signing-input validator `assert_sign_inputs` omits this check entirely. A caller — including a malicious coordinator — can supply `threshold = 1` to any FROST signing entry point, bypassing the documented minimum-threshold security property and corrupting the Lagrange interpolation used to aggregate signing shares.

### Finding Description

`assert_key_invariants` in `src/dkg.rs` explicitly rejects any threshold below 2:

```rust
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

`assert_sign_inputs` in `src/frost/mod.rs`, which gates every FROST EdDSA signing call (`sign_v1`, `sign_v2`), performs only an upper-bound check and never a lower-bound check:

```rust
// validate threshold
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check: threshold.value() < 2
``` [2](#0-1) 

The `ThresholdTooSmall` error variant exists in the error enum and is used by DKG, confirming the codebase's intent to enforce this bound universally: [3](#0-2) 

Because `assert_sign_inputs` is the sole validation gate before the FROST signing future is spawned, passing `threshold = 1` reaches the protocol execution path unchecked. [4](#0-3) 

### Impact Explanation

In FROST, the `threshold` (reconstruction lower bound) governs Lagrange interpolation of signing shares. When `threshold = 1` is supplied but the DKG was conducted with `threshold = 2` (degree-1 polynomial), the Lagrange coefficients are computed for a degree-0 polynomial. Each participant's normalized share becomes their raw share rather than the correctly weighted contribution, so the aggregated group commitment and response scalar do not satisfy the verification equation. Honest participants produce and accept a cryptographically unusable signature — matching the allowed impact: **High: Corruption of sign outputs so honest parties accept inconsistent or unusable cryptographic outputs.**

### Likelihood Explanation

The coordinator is an explicit, named role in the FROST signing API (`coordinator: Participant` parameter). A malicious coordinator constructs the `sign_v1` / `sign_v2` call with `threshold = 1` and a valid participant list of size ≥ 2 (satisfying the only enforced lower bound). No key compromise or cryptographic break is required; the attacker only needs to be the designated coordinator for a signing session.

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` uses:

```rust
// In assert_sign_inputs, after the upper-bound check:
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
``` [5](#0-4) 

### Proof of Concept

1. Run DKG with 3 participants and `threshold = 2` → each party holds a share of a degree-1 polynomial.
2. Call `sign_v1(participants, threshold = 1, me, coordinator, keygen_output, message, rng)`.
3. `assert_sign_inputs` accepts `threshold = 1` because `1 <= participants.len()` and the `< 2` guard is absent.
4. The FROST signing future executes with `threshold = 1`; Lagrange coefficients are computed for a degree-0 polynomial.
5. The aggregated signature fails verification against the public key produced by step 1, leaving honest parties with an unusable output.

### Citations

**File:** src/dkg.rs (L580-582)
```rust
    if threshold < 2 {
        return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
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

**File:** src/errors.rs (L140-142)
```rust
    #[error("threshold {threshold} is too small, it must be at least {min}")]
    ThresholdTooSmall { threshold: usize, min: usize },

```
