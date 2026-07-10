### Title
Missing Lower-Bound Threshold Validation in FROST Signing Initialization — (`File: src/frost/mod.rs`)

---

### Summary

The FROST signing initialization functions `presign()` and `assert_sign_inputs()` in `src/frost/mod.rs` validate that `threshold` does not exceed the participant count, but omit the symmetric lower-bound check (`threshold >= 2`) that is enforced in the DKG path. A caller supplying `threshold = 1` passes all guards silently, causing the signing protocol to run Lagrange interpolation over a single share, producing a cryptographically invalid (unusable) aggregate signature.

---

### Finding Description

`assert_key_invariants` in `src/dkg.rs` enforces both bounds on the threshold:

```rust
// src/dkg.rs  lines 573-582
if threshold > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
if threshold < 2 {
    return Err(InitializationError::ThresholdTooSmall { threshold, min: 2 });
}
``` [1](#0-0) 

The FROST signing path applies only the upper-bound check and never the lower-bound check:

```rust
// src/frost/mod.rs  lines 71-77  (presign)
if args.threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check for threshold < 2
``` [2](#0-1) 

```rust
// src/frost/mod.rs  lines 144-150  (assert_sign_inputs)
if threshold.value() > participants.len() {
    return Err(InitializationError::ThresholdTooLarge { ... });
}
// ← no check for threshold < 2
``` [3](#0-2) 

`ReconstructionLowerBound` is a plain `usize` newtype with no invariant enforced at construction time, so `threshold = 1` (or `0`) is a representable value that flows through both functions without rejection. [4](#0-3) 

When `threshold = 1` reaches the signing protocol, Lagrange interpolation is performed over a single participant's share with coefficient `λ = 1`. The resulting partial signature `z₁ = nonce₁ + challenge · share₁` is aggregated as the final signature `(R, z₁)`. Verification requires `z₁·G = R + challenge·PK`, which expands to `R₁ + challenge·PK₁ = R + challenge·PK`. Because `R = ΣRᵢ` and `PK = ΣPKᵢ` across all participants, the equation fails for any multi-party key, making the signature permanently unusable.

---

### Impact Explanation

Every honest participant expends nonce material and a partial-signature computation, yet the aggregated output is a cryptographically invalid signature that cannot be verified against the shared public key. This matches the allowed High impact: **corruption of sign outputs so honest parties accept unusable cryptographic outputs**. The nonce material consumed during the failed signing round is also irrecoverably spent, contributing to resource exhaustion for repeated invocations.

---

### Likelihood Explanation

The entry point is the public API: any caller of `presign()` or `assert_sign_inputs()` controls the `threshold` argument directly. A malicious coordinator, a misconfigured orchestration layer, or a library consumer who mistakenly passes `1` (e.g., intending "1-of-N") can trigger this path. No privileged access or cryptographic break is required — only the ability to call the public signing initialization functions with an out-of-range threshold value.

---

### Recommendation

Add the same lower-bound guard that `assert_key_invariants` already enforces, in both `presign()` and `assert_sign_inputs()`:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This mirrors the existing pattern in `src/dkg.rs` lines 580–582 and closes the asymmetry between the DKG and signing initialization paths. [5](#0-4) 

---

### Proof of Concept

1. Run DKG with `participants = [P1, P2, P3]`, `threshold = 2` — succeeds and produces a valid shared key.
2. Call `presign(participants, me, PresignArguments { threshold: 1.into(), keygen_out }, rng)` — no `InitializationError` is returned; the protocol starts.
3. Proceed to the signing round with `threshold = 1`; Lagrange interpolation uses only `P1`'s share.
4. The aggregate signature `(R, z₁)` fails `verify(public_key, message, signature)` because `z₁·G ≠ R + challenge·PK`.
5. All participants have irrevocably consumed their nonce commitments for a signing session that can never produce a valid output.

The root cause is the missing `threshold < 2` guard in `src/frost/mod.rs` lines 44–88 and 120–159, absent from both `presign` and `assert_sign_inputs`, while the identical guard is present in `src/dkg.rs` lines 580–582. [6](#0-5) [7](#0-6)

### Citations

**File:** src/dkg.rs (L573-582)
```rust
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
