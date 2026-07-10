### Title
Missing Lower-Bound Threshold Validation in FROST Presign and Sign Allows Corrupted Signature Outputs - (File: src/frost/mod.rs)

### Summary
The FROST presign and sign input validation functions in `src/frost/mod.rs` only enforce an upper-bound check on the `threshold` parameter (`threshold <= participants.len()`), but omit the lower-bound check (`threshold >= 2`) that is consistently enforced everywhere else in the codebase. A caller can pass `threshold = 1` (or `threshold = 0`) to FROST presign/sign, causing Lagrange interpolation to be computed with an incorrect reconstruction bound relative to the key that was generated, producing a corrupted and unusable signature output.

### Finding Description

`ReconstructionLowerBound` is a plain `usize` newtype with no built-in minimum enforcement: [1](#0-0) 

In `src/frost/mod.rs`, the `presign` function validates threshold only against an upper bound: [2](#0-1) 

Similarly, `assert_sign_inputs` (called by EdDSA and RedJubjub sign functions) only checks the upper bound: [3](#0-2) 

There is no `threshold < 2` guard in either function. By contrast, every other threshold-consuming entry point in the codebase enforces a minimum of 2. Triple generation in the OT-based ECDSA path explicitly rejects `threshold_value < 2`: [4](#0-3) 

And DKG keygen/reshare enforce the same minimum, as confirmed by the test helpers: [5](#0-4) 

The FROST presign and sign paths are the only public entry points that skip this check entirely.

### Impact Explanation

When `threshold = 1` is supplied to FROST presign or sign, the Lagrange interpolation used to combine partial signatures is computed with a reconstruction bound of 1. Because the underlying key was generated with `threshold >= 2` (enforced by DKG), the Lagrange coefficients computed during signing are inconsistent with the polynomial degree of the secret sharing. The resulting combined signature is cryptographically invalid and unusable. Honest parties who run the protocol with this misconfigured threshold will complete the protocol without error but receive a corrupted output — matching the **High** allowed impact: *Corruption of sign outputs so honest parties accept unusable cryptographic outputs*.

### Likelihood Explanation

The FROST presign and sign functions are public library API entry points. Any unprivileged caller constructing a `PresignArguments` struct with `threshold: ReconstructionLowerBound(1)` can trigger this path directly. No special privilege, key material, or network access is required. The `ReconstructionLowerBound` type accepts any `usize` value with no restriction. [6](#0-5) 

### Recommendation

Add a lower-bound check in both `presign` and `assert_sign_inputs` in `src/frost/mod.rs`, consistent with the rest of the codebase:

```rust
if threshold.value() < 2 {
    return Err(InitializationError::ThresholdTooSmall {
        threshold: threshold.value(),
        min: 2,
    });
}
```

This should be inserted before the upper-bound check in both functions, mirroring the pattern in `validate_triple_inputs`.

### Proof of Concept

1. A caller runs DKG with `threshold = 2` and `participants = [A, B, C]`, producing valid key shares.
2. The same caller invokes `frost::presign` (or the EdDSA/RedJubjub sign function via `assert_sign_inputs`) with `threshold = ReconstructionLowerBound(1)` and the same participant list.
3. Both functions accept the call — no error is returned because only the upper-bound check (`1 > 3`) is evaluated, which passes.
4. The signing protocol proceeds, computing Lagrange coefficients for a degree-0 polynomial (threshold-1 = 0) instead of the degree-1 polynomial used during key generation.
5. The combined signature is cryptographically invalid. All honest participants complete the protocol and accept the output, but the signature fails external verification against the master public key. [7](#0-6) [8](#0-7)

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

**File:** src/frost/mod.rs (L25-30)
```rust
pub struct PresignArguments<C: Ciphersuite> {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput<C>,
    /// The threshold for the scheme
    pub threshold: ReconstructionLowerBound,
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

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L699-704)
```rust
    if threshold_value < 2 {
        return Err(InitializationError::ThresholdTooSmall {
            threshold: threshold_value,
            min: 2,
        });
    }
```

**File:** src/dkg.rs (L738-756)
```rust
    pub fn keygen__should_fail_if_threshold_is_below_limit<
        C: Ciphersuite,
        R: CryptoRngCore + SeedableRng + Send + 'static,
    >(
        rng: &mut R,
    ) where
        <C::Group as Group>::Element: std::fmt::Debug + std::marker::Send,
        <<C::Group as Group>::Field as Field>::Scalar: std::marker::Send,
    {
        let threshold = 1;
        let participants = generate_participants(2);

        let rng_keygen = R::seed_from_u64(rng.next_u64());
        let result = keygen::<C>(&participants, participants[0], threshold, rng_keygen);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::ThresholdTooSmall { threshold, min: 2 }
        );
```
